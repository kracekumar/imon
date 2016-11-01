use std::path::Path;
use std::fs::File;
use time;
use rusqlite::Connection;
use chrono;
use chrono::offset::utc::UTC;


#[derive(Debug)]
pub struct Traffic {
    id: i32,
    domain_name: String,
    data_consumed_in_bytes: u32,
    date: chrono::date::Date<UTC>,
    created_at: time::Timespec,
    updated_at: time::Timespec,
}


fn create_db(conn: &Connection){
    /* Create SQLite db */
    conn.execute("create table traffic (
id integer primary key,
domain_name varchar(128) not null,
data_consumed_in_bytes integer not null,
date date not null,
created_at datetime not null,
updated_at datetime not null
)
", &[]).unwrap();
}


pub fn create_conn() -> Connection{
    // TODO: Refactor to read from config file
    let path = Path::new("imon.db");
    if path.exists() {
        Connection::open(path).unwrap()
    } else {
        match File::create(path) {
            Ok(file) => {
                let conn = Connection::open(path).unwrap();
                create_db(&conn);
                conn
            },
            Err(err) => {
                panic!("Unable to create db at {:?}, error: {:?}", path, err);
            }
        }
        
    }
}
