use HubResult;


fn convert_to_human_readable_format(count: u64) ->(f64, String){
    /*
    Given number of bytes convert to tuple.
    First element contains value less than 1023 and second
    element represents the unit.
    */
    let units = ["B", "KB", "MB", "GB"];
    let base = 1024f64;
    let mut lowest_count = count as f64;
    let mut final_unit = "";
    for unit in units.iter(){
        if lowest_count < base {
            final_unit = unit;
            break; 
        }
        lowest_count = lowest_count / base;
    }
    (lowest_count, final_unit.to_string())
}


pub fn display_report(hub_result: &HubResult, command: &str){
    /* Display the results obtained from daemon.

    Output varies depend on type of query.
    */
    for (index, result) in hub_result.result.iter().enumerate(){
        let (val, format) = convert_to_human_readable_format(result.1 as u64);
        match command {
            "site" => {
                // Using info! macro adds `info` at the start of the line. So using println!
                println!("{:?}| {}| {:.2?} {:?}| {:?}", index, result.0, val, format, result.2);
            },
            "report" => {
                println!("{:?}| {}| {:.2?} {:?}", index, result.0, val, format);
            },
            _ => {}
        }
    }
}


#[test]
fn test_convert_to_human_readable_format(){
    assert_eq!(convert_to_human_readable_format(1000), (1000f64, "B".to_string()));
    assert_eq!(convert_to_human_readable_format(1024), (1f64, "KB".to_string()));
    assert_eq!(convert_to_human_readable_format(10249), (10.0087890625, "KB".to_string()));
    assert_eq!(convert_to_human_readable_format(10249000), (9.774208068847656, "MB".to_string()));
    assert_eq!(convert_to_human_readable_format(10249000000), (9.54512506723404, "GB".to_string()));
}
