extern "C" {
    pub fn get_block_hash(req: Vec<u8>) -> Vec<u8>;
    pub fn get_account(req: Vec<u8>) -> Vec<u8>;
    pub fn contains_key(req: Vec<u8>) -> Vec<u8>;
    pub fn get_storage_cell(req: Vec<u8>) -> Vec<u8>;
    pub fn get_account_code(req: Vec<u8>) -> Vec<u8>;
    pub fn insert_account(req: Vec<u8>) -> Vec<u8>;
    pub fn insert_account_code(req: Vec<u8>) -> Vec<u8>;
    pub fn insert_storage_cell(req: Vec<u8>) -> Vec<u8>;
    pub fn remove(req: Vec<u8>) -> Vec<u8>;
    pub fn remove_storage_cell(req: Vec<u8>) -> Vec<u8>;
}
