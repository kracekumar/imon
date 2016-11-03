use std::path::Path;
use std::fs::File;
use time;
use rusqlite::{Connection, MappedRows, Row};
use rusqlite::types::{FromSql, ToSql};
use chrono;
use chrono::offset::utc::UTC;
use chrono::NaiveDate;

use rusqlite::{Result, Error};


fn get_current_datetime() -> chrono::DateTime<UTC>{
    UTC::now()
}


fn get_current_date() -> NaiveDate{
    get_current_datetime().date().naive_utc()
}


#[derive(Debug)]
pub struct Traffic {
    id: i32,
    domain_name: String,
    data_consumed_in_bytes: i64,
    date: NaiveDate,
    created_at: time::Timespec,
    updated_at: time::Timespec,
}


impl Traffic{
    fn create(domain_name: String, data_consumed_in_bytes: i64, conn: &Connection){
        /* Create a new traffic object
         */
        let cur_datetime = time::get_time();
        let date = get_current_date();
        let traffic = Traffic{id: 0, domain_name: domain_name, data_consumed_in_bytes: data_consumed_in_bytes,
                              date: date, created_at: cur_datetime, updated_at: cur_datetime};
        conn.execute("Insert into traffic (domain_name, data_consumed_in_bytes, date, created_at, updated_at)
values ($1, $2, $3, $4, $5)", &[&traffic.domain_name, &traffic.data_consumed_in_bytes, &traffic.date,
                                &traffic.created_at, &traffic.updated_at]);
    }

    fn filter(domain_name: String, conn: &Connection) -> Option<Result<Traffic>>{
        /* Check whether domain_name and date matching record exists
         */
        let date = get_current_date();
        let sql_stmt = format!("select id, domain_name, data_consumed_in_bytes, date, created_at, updated_at from 
        traffic where domain_name={:?} and date=\"{:?}\"", domain_name.to_string(), date);
        let mut stmt = conn.prepare(&sql_stmt).unwrap();
        let mut qs = stmt.query_map(&[], |row|{
            Traffic{
                id: row.get(0),
                domain_name: row.get(1),
                data_consumed_in_bytes: row.get(2),
                date: row.get(3),
                created_at: row.get(4),
                updated_at: row.get(5),
            }
            
        }).unwrap();
        qs.next()
    }

    fn update(record: Traffic, data_consumed_in_bytes: i64, conn: &Connection){
        /* Update the record
         */
        let cur_datetime = time::get_time();
        let quantity: i64 = record.data_consumed_in_bytes + data_consumed_in_bytes;
        let date = get_current_date();
        let res = conn.execute("update traffic set data_consumed_in_bytes = $1, updated_at = $2 where id = $3",
                     &[&quantity, &cur_datetime, &record.id]).unwrap();
        if res == 1 {
            println!("Updated succedded: {}", quantity);
        } else {
            println!("Update failed");
        }
    }
    
    pub fn create_or_update(domain_name: String, data_consumed_in_bytes: i64, conn: &Connection){
        let qs = Traffic::filter(domain_name.clone(), conn);
        match qs{
            Some(record) => {
                /* Update the record */
                Traffic::update(record.unwrap(), data_consumed_in_bytes, conn);
            },
            None => {
                /* create a new record */
                println!("No record found");
                Traffic::create(domain_name.clone(), data_consumed_in_bytes, conn);
            }
        }
    }
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
);
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
