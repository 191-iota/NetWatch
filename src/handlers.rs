use actix_web::HttpResponse;
use actix_web::web;

use crate::get_db_alerts;
use crate::get_db_device_by_ip;
use crate::get_db_devices;
use crate::models::AppState;

pub async fn get_devices(state: web::Data<AppState>) -> HttpResponse {
    let mut conn = state.connection_pool.lock().unwrap();
    match get_db_devices(&mut conn) {
        Ok(devices) => HttpResponse::Ok().json(devices),
        Err(_) => HttpResponse::InternalServerError().body("Failed fetching devices"),
    }
}

pub async fn get_device_by_ip(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    // TODO: Implement better security to validate ip
    let mut conn = state.connection_pool.lock().unwrap();
    match get_db_device_by_ip(&mut conn, path.into_inner()) {
        Ok(devices) => HttpResponse::Ok().json(devices),
        Err(_) => HttpResponse::NotFound().body("Device not found"),
    }
}

pub async fn get_alerts(state: web::Data<AppState>) -> HttpResponse {
    let mut conn = state.connection_pool.lock().unwrap();
    match get_db_alerts(&mut conn) {
        Ok(alerts) => HttpResponse::Ok().json(alerts),
        Err(_) => HttpResponse::NotFound().body("Device not found"),
    }
}
