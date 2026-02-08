use actix_web::HttpRequest;
use actix_web::HttpResponse;
use actix_web::Result;
use actix_web::web;

use crate::models::AppState;

pub async fn ws_alert(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // Websocket handshake
    let (res, mut session, _) = actix_ws::handle(&req, body)?;
    let mut rx = state.alert_tx.subscribe();

    actix_web::rt::spawn(async move {
        // This loop keeps the connection alive
        while let Ok(alert) = rx.recv().await {
            let json = serde_json::to_string(&alert).unwrap();
            if session.text(json).await.is_err() {
                break;
            }
        }
    });

    Ok(res)
}
