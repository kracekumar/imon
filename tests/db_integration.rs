extern crate imon;
extern crate rusqlite;

use std::fs;


const DB_PATH: &'static str = "test_imon.db";


fn create_test_conn() -> rusqlite::Connection{
    imon::db::create_conn(Some(DB_PATH))
}


fn tear_down(){
    let res = fs::remove_file(DB_PATH);
    match res {
        Ok(_) => {},
        Err(e) => {println!("Error: {:?}", e)}
    }
}


#[test]
fn test_insert_or_update(){
    let conn = create_test_conn();
    let res = imon::db::Traffic::create_or_update("kracekumar".to_string(), 23000, &conn);

    assert_eq!(res.0, "create".to_string());
    assert_eq!(res.1, 1);

    // Since record exists, method should update
    let res = imon::db::Traffic::create_or_update("kracekumar".to_string(), 23000, &conn);
    assert_eq!(res.0, "update".to_string());
    assert_eq!(res.1, 1);

    tear_down();
}
