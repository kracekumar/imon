fn convert_to_human_readable_format(count: u64) ->(f64, String){
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


#[test]
fn test_convert_to_human_readable_format(){
    assert_eq!(convert_to_human_readable_format(1000), (1000f64, "B".to_string()));
    assert_eq!(convert_to_human_readable_format(1024), (1f64, "KB".to_string()));
    assert_eq!(convert_to_human_readable_format(10249), (10.0087890625, "KB".to_string()));
    assert_eq!(convert_to_human_readable_format(10249000), (9.774208068847656, "MB".to_string()));
    assert_eq!(convert_to_human_readable_format(10249000000), (9774.208068847656, "GB".to_string()));
}
