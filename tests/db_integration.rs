extern crate imon;
extern crate rusqlite;
#[macro_use] extern crate log;
extern crate env_logger;

use std::fs;


const DB_PATH: &'static str = "test_imon.db";


fn create_test_conn() -> rusqlite::Connection{
    imon::db::create_conn(Some(DB_PATH))
}


fn tear_down(conn: &rusqlite::Connection){
    imon::db::delete_table(conn);
    let res = fs::remove_file(DB_PATH);
    match res {
        Ok(_) => {},
        Err(e) => {debug!("Error: {:?}", e)}
    }
}



fn insert_or_update(){
    let conn = create_test_conn();
    let res = imon::db::Traffic::create_or_update("kracekumar".to_string(), 23000, &conn);

    assert_eq!(res.0, "create".to_string());
    assert_eq!(res.1, 1);

    // Since record exists, method should update
    let res = imon::db::Traffic::create_or_update("kracekumar".to_string(), 23000, &conn);
    assert_eq!(res.0, "update".to_string());
    assert_eq!(res.1, 1);

    tear_down(&conn);
    let _ = conn.close();
}


fn report_today(){
    let conn = create_test_conn();
    let _ = imon::db::Traffic::create_or_update("kracekumar.com".to_string(), 23000, &conn);

    let traffic = imon::db::Traffic::report_today(&conn);

    assert_eq!(traffic[0].domain_name, "kracekumar.com".to_string());
    assert_eq!(traffic[0].data_consumed_in_bytes, 23000);

    tear_down(&conn);
    let _ = conn.close();
}


fn report_by_date_range(){
    let conn = create_test_conn();
    let _ = imon::db::Traffic::create_or_update("kracekumar.com".to_string(), 23000, &conn);

    let date = format!("{}", imon::db::get_current_date().format("%Y-%m-%d"));
    let traffic = imon::db::Traffic::report_by_date_range(date.clone(), date, &conn);

    assert_eq!(traffic[0].domain_name, "kracekumar.com".to_string());
    assert_eq!(traffic[0].data_consumed_in_bytes, 23000);

    tear_down(&conn);
    let _ = conn.close();
}


fn filter_site(){
    let conn = create_test_conn();
    let _ = imon::db::Traffic::create_or_update("kracekumar.com".to_string(), 23000, &conn);

    let traffic = imon::db::Traffic::filter_site("kracekumar.com".to_string(), &conn);

    assert_eq!(traffic[0].domain_name, "kracekumar.com".to_string());
    assert_eq!(traffic[0].data_consumed_in_bytes, 23000);

    tear_down(&conn);
    let _ = conn.close();
}


fn filter_site_by_date_range(){
    let conn = create_test_conn();
    let _ = imon::db::Traffic::create_or_update("kracekumar.com".to_string(), 23000, &conn);

    let date = format!("{}", imon::db::get_current_date().format("%Y-%m-%d"));
    let traffic = imon::db::Traffic::filter_site_by_date_range("kracekumar.com".to_string(), date.clone(), date, &conn);

    assert_eq!(traffic[0].domain_name, "kracekumar.com".to_string());
    assert_eq!(traffic[0].data_consumed_in_bytes, 23000);

    tear_down(&conn);
    let _ = conn.close();
}


fn main(){
    insert_or_update();
    report_today();
    report_by_date_range();
    filter_site();
    filter_site_by_date_range();
}
