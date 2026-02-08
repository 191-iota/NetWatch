use rusqlite::Connection;
use rusqlite::Result;

pub fn check_alert_new_device(conn: &mut Connection, ip: &String) -> Result<bool> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE ip = ?1)",
        [&ip],
        |row| row.get(0),
    )?;

    Ok(exists)
}
