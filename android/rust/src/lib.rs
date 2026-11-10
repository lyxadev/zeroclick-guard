//! JNI bridge: exposes the exact same `zcg-core` engine to the Android app.
//!
//! This is the whole point of Level 3 — not a reimplementation, but the same
//! Rust engine (`zcg_core::Engine`) compiled for the device and called from
//! Kotlin. The Kotlin side is `ai.lyxvo.zeroclickguard.NativeEngine`.

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;

use zcg_core::{Config, Engine, IocSet, Observation};

/// Create an engine and return an opaque handle (a boxed pointer as jlong).
#[no_mangle]
pub extern "system" fn Java_ai_lyxvo_zeroclickguard_NativeEngine_create(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let engine = Box::new(Engine::new(Config::default(), IocSet::new()));
    Box::into_raw(engine) as jlong
}

/// Feed one observed flow into the engine; return the app's current total score.
///
/// # Safety
/// `handle` must be a pointer returned by `create` and not yet destroyed.
#[no_mangle]
pub extern "system" fn Java_ai_lyxvo_zeroclickguard_NativeEngine_observeFlow(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    ts: jlong,
    app: JString,
    background: jboolean,
    dst_ip: JString,
    dst_port: jint,
    bytes_out: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let engine = unsafe { &mut *(handle as *mut Engine) };
    let app: String = env
        .get_string(&app)
        .map(|s| s.into())
        .unwrap_or_default();
    let dst_ip: String = env
        .get_string(&dst_ip)
        .map(|s| s.into())
        .unwrap_or_default();

    engine.process(Observation::Flow {
        ts: ts as u64,
        app: app.clone(),
        app_background: background != 0,
        dst_ip,
        dst_port: dst_port as u16,
        domain: None,
        bytes_out: bytes_out as u64,
        bytes_in: 0,
        proto: "tcp".to_string(),
    });

    engine
        .verdicts()
        .into_iter()
        .find(|v| v.app == app)
        .map(|v| v.score as jint)
        .unwrap_or(0)
}

/// Destroy an engine handle.
///
/// # Safety
/// `handle` must be a pointer returned by `create`, destroyed at most once.
#[no_mangle]
pub extern "system" fn Java_ai_lyxvo_zeroclickguard_NativeEngine_destroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            drop(Box::from_raw(handle as *mut Engine));
        }
    }
}
