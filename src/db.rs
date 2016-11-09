use std::path::Path;
use std::fs::File;
use time;
use rusqlite::{Connection, Statement};
//use rusqlite::types::{FromSql};
use chrono;
use chrono::offset::utc::UTC;
use chrono::NaiveDate;

use rusqlite::{Result};
use TrafficTuple;


fn get_current_datetime() -> chrono::DateTime<UTC>{
    UTC::now()
}


pub fn get_current_date() -> NaiveDate{
    get_current_datetime().date().naive_utc()
}


#[derive(Debug, Clone)]
pub struct Traffic {
    id: i32,
    domain_name: String,
    data_consumed_in_bytes: i64,
    date: NaiveDate,
    created_at: time::Timespec,
    updated_at: time::Timespec,
}


fn unpack(stmt: &mut Statement, fill_date: bool, fill_audit_fields: bool, fill_id: bool) -> Vec<Traffic>{
    let mut res: Vec<Traffic> = Vec::new();
    // TODO: This is complicated, what's the better way?
    if !fill_date & !fill_audit_fields & !fill_id{
        // unpack(&mut stmt, false, false, false)
        let qs = stmt.query_map(&[], |row|{
            Traffic{
                id: row.get(0),
                domain_name: row.get(1),
                data_consumed_in_bytes: row.get(2),
                date: row.get(3),
                created_at: row.get(4),
                updated_at: row.get(5),
            }
        }).unwrap();
        for traffic in qs {
            res.push(traffic.unwrap());
        }
    } else if fill_date & fill_audit_fields & fill_id{
        // unpack(&mut stmt, true, true, false)
        let date = get_current_date();
        let audit_value = time::get_time();
        let qs = stmt.query_map(&[], |row|{
            Traffic{
                id: 0,
                domain_name: row.get(0),
                data_consumed_in_bytes: row.get(1),
                date: date,
                created_at: audit_value,
                updated_at: audit_value,
            }
        }).unwrap();
        for traffic in qs {
            res.push(traffic.unwrap());
        }
    } else if !fill_date & fill_audit_fields & fill_id {
        // unpack(&mut stmt, false, true, true)
        let audit_value = time::get_time();
        let qs = stmt.query_map(&[], |row|{
            Traffic{
                id: 0,
                domain_name: row.get(0),
                data_consumed_in_bytes: row.get(1),
                date: row.get(2),
                created_at: audit_value,
                updated_at: audit_value,
            }
        }).unwrap();
        for traffic in qs {
            res.push(traffic.unwrap());
        }
    } else {
        // pass
    }
    res
}


impl Traffic{
    pub fn to_tuple(self) -> TrafficTuple{
        (self.domain_name, self.data_consumed_in_bytes,
        format!("{}", self.date.format("%Y-%m-%d")))
    }

    fn create(domain_name: String, data_consumed_in_bytes: i64, conn: &Connection) -> i32{
        /* Create a new traffic object
         */
        let cur_datetime = time::get_time();
        let date = get_current_date();
        let traffic = Traffic{id: 0, domain_name: domain_name, data_consumed_in_bytes: data_consumed_in_bytes,
                              date: date, created_at: cur_datetime, updated_at: cur_datetime};
        let res = conn.execute("Insert into traffic (domain_name, data_consumed_in_bytes, date, created_at, updated_at)
values ($1, $2, $3, $4, $5)", &[&traffic.domain_name, &traffic.data_consumed_in_bytes, &traffic.date,
                                &traffic.created_at, &traffic.updated_at]);
        res.unwrap()
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

    fn update(record: Traffic, data_consumed_in_bytes: i64, conn: &Connection) -> i32{
        /* Update the record
         */
        let cur_datetime = time::get_time();
        let quantity: i64 = record.data_consumed_in_bytes + data_consumed_in_bytes;
        let res = conn.execute("update traffic set data_consumed_in_bytes = $1, updated_at = $2 where id = $3",
                     &[&quantity, &cur_datetime, &record.id]).unwrap();
        if res == 1 {
            println!("Updated succedded for {}: {}", record.domain_name, quantity);
        } else {
            println!("Update failed");
        }
        res
    }
    
    pub fn create_or_update(domain_name: String, data_consumed_in_bytes: i64, conn: &Connection) -> (String, i32){
        let qs = Traffic::filter(domain_name.clone(), conn);
        match qs{
            Some(record) => {
                /* Update the record */
                let res = Traffic::update(record.unwrap(), data_consumed_in_bytes, conn);
                ("update".to_string(), res)
            },
            None => {
                /* create a new record */
                let res = Traffic::create(domain_name.clone(), data_consumed_in_bytes, conn);
                ("create".to_string(), res)
            }
        }
    }
    // Reporting functions
    pub fn report_today(conn: &Connection) -> Vec<Traffic>{
        let date = get_current_date();
        let sql_stmt = format!("select id, domain_name, data_consumed_in_bytes, date, created_at, updated_at from
        traffic where date=\"{:?}\" order by data_consumed_in_bytes desc", date);
        let mut stmt = conn.prepare(&sql_stmt).unwrap();
        unpack(&mut stmt, false, false, false)
    }

    pub fn report_by_date_range(start_date: String, end_date: String, conn: &Connection) -> Vec<Traffic>{
        let sql_stmt = format!("select domain_name, sum(data_consumed_in_bytes) as total from traffic where date between {:?} and {:?} group by domain_name order by total desc", start_date, end_date);
        let mut stmt = conn.prepare(&sql_stmt).unwrap();
        unpack(&mut stmt, true, true, true)
    }

    // site specific queries
    pub fn filter_site(domain_name: String, conn: &Connection) -> Vec<Traffic>{
        let sql_stmt = format!("select domain_name, data_consumed_in_bytes, date from traffic where domain_name={:?}",
                               domain_name);
        let mut stmt = conn.prepare(&sql_stmt).unwrap();
        unpack(&mut stmt, false, true, true)
    }

    pub fn filter_site_by_date_range(domain_name: String, start_date: String,
                                end_date: String, conn: &Connection) -> Vec<Traffic>{
        let sql_stmt = format!("select domain_name, data_consumed_in_bytes, date from traffic where domain_name={:?} and
date between {:?} and {:?}",
                               domain_name, start_date, end_date);
        let mut stmt = conn.prepare(&sql_stmt).unwrap();
        unpack(&mut stmt, false, true, true)
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


pub fn create_conn(file_path: Option<&'static str>) -> Connection{
    // TODO: Refactor to read from config file
    let path = match file_path{
        Some(val) => val,
        None => "imon.db"
    };
    let path = Path::new(path);
    if path.exists() {
        Connection::open(path).unwrap()
    } else {
        match File::create(path) {
            Ok(_) => {
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
