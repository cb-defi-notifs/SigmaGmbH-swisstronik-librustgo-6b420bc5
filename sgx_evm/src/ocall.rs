use crate::querier::GoQuerier;

extern "C" {
    pub fn get_block_hash(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn get_account(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn contains_key(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn get_storage_cell(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn get_account_code(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn insert_account(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn insert_account_code(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn insert_storage_cell(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn remove(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
    pub fn remove_storage_cell(q: GoQuerier, req: Vec<u8>) -> Vec<u8>;
}
