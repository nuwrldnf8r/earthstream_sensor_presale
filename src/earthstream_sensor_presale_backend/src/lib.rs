#![allow(non_snake_case)]
mod evm_rpc;
use evm_rpc::{
    RpcApi, EvmRpcCanister, RpcService, RequestResult, CANISTER_ID
};
use ic_cdk::{self, api::call::CallResult};
use candid::{CandidType};
use serde::{Deserialize, Serialize};
use std::string::String;
use ic_cdk::export::Principal;
use std::collections::HashMap;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Transaction {
    pub chain_id: Vec<u8>, // BigUint64Array equivalent
    pub txhash: String,
    pub token_type: TokenType,
    pub contract_address: String,
    pub amount: u64, // Amount in wei
    pub from_address: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Sensor {
    pub sensor_id: String,
    pub sensor_type: SensorType,
    pub owner: Principal,
    pub assign_type: AssignType,
    pub project_id: Option<String>,
    pub purchase_date: Option<u64>, // Timestamp in seconds
    pub transaction: Option<Transaction>,
    pub status: SensorStatus,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum SensorType {
    GSM,
    LORA,
    GATEWAY_GSM,
    GATEWAY_WIFI,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum AssignType {
    OWNER,
    PROJECT,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum SensorStatus {
    PRESALE,
    PROCESSING_FOR_SHIPPING,
    SHIPPED,
    DEPLOYED,
    OFFLINE,
    QUERY,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum TokenType {
    NATIVE,
    ERC20,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct User {
    pub principal: Principal,
    pub address: String, // EVM address
    pub discord_handle: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct AcceptedToken {
    pub token_id: String,
    pub chain_id: Vec<u8>, // BigUint64Array equivalent
    pub rpc_url: String,
    pub token_type: TokenType,
    pub contract_address: Option<String>, // Optional for NATIVE tokens
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SensorPrice {
    pub sensor_type: SensorType,
    pub prices: Vec<TokenPrice>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct TokenPrice {
    pub token_id: String,
    pub amount: u64, // Amount in wei
}

// Canister state
#[derive(Default)]
pub struct CanisterState {
    pub sensors: HashMap<String, Sensor>,
    pub users: HashMap<Principal, User>,
    pub accepted_tokens: Vec<AcceptedToken>,
    pub sensor_prices: Vec<SensorPrice>,
    pub admins: Vec<Principal>,
    pub super_admin: Option<Principal>,
}

impl CanisterState {
    pub fn new() -> Self {
        Self {
            sensors: HashMap::new(),
            users: HashMap::new(),
            accepted_tokens: Vec::new(),
            sensor_prices: Vec::new(),
            admins: Vec::new(),
            super_admin: None,
        }
    }
}

// Canister logic skeleton
impl CanisterState {
    pub fn purchase_sensor(
        &mut self,
        sensor_id: String,
        txhash: String,
        caller: Principal,
        amount: u64,
        token_type: TokenType,
        contract_address: String,
        from_address: String,
    ) -> Result<(), String> {
        if let Some(sensor) = self.sensors.get_mut(&sensor_id) {
            if sensor.transaction.is_some() {
                return Err("Transaction details cannot be updated.".to_string());
            }
            sensor.transaction = Some(Transaction {
                chain_id: vec![],
                txhash,
                token_type,
                contract_address,
                amount,
                from_address,
            });
            sensor.owner = caller;
            sensor.purchase_date = Some(ic_cdk::api::time() / 1_000_000); // Convert from nanoseconds to seconds
            Ok(())
        } else {
            Err("Sensor ID not found.".to_string())
        }
    }

    pub fn list_sensors_by_owner(&self, owner: Principal) -> Vec<Sensor> {
        self.sensors
            .values()
            .filter(|sensor| sensor.owner == owner)
            .cloned()
            .collect()
    }
    
    pub fn list_sensors_by_project(&self, project_id: String) -> Vec<Sensor> {
        self.sensors
            .values()
            .filter(|sensor| sensor.project_id.as_deref() == Some(&project_id))
            .cloned()
            .collect()
    }
    
    pub fn list_sensors_by_type_and_date(
        &self,
        sensor_type: SensorType,
        start_date: u64,
        end_date: u64,
    ) -> Vec<Sensor> {
        self.sensors
            .values()
            .filter(|sensor| {
                sensor.sensor_type == sensor_type
                    && sensor
                        .purchase_date
                        .map_or(false, |date| date >= start_date && date <= end_date)
            })
            .cloned()
            .collect()
    }
    
    pub fn count_sensors_by_type(&self) -> HashMap<SensorType, usize> {
        let mut counts = HashMap::new();
        for sensor in self.sensors.values() {
            *counts.entry(sensor.sensor_type.clone()).or_insert(0) += 1;
        }
        counts
    }
}
    


#[derive(CandidType, Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<String>, 
    id: u64,
}


#[derive(Debug, Deserialize)]
pub struct TransactionResult {
    pub id: u64,
    pub jsonrpc: String,
    pub result: TransactionDetails,
}

#[derive(Debug, Deserialize)]
pub struct TransactionDetails {
    pub accessList: Vec<String>, // Empty list in this case
    pub blockHash: String,
    pub blockNumber: String,
    pub chainId: String,
    pub from: String,
    pub gas: String,
    pub gasPrice: String,
    pub hash: String,
    pub input: String,
    pub maxFeePerGas: String,
    pub maxPriorityFeePerGas: String,
    pub nonce: String,
    pub r: String,
    pub s: String,
    pub to: String,
    pub transactionIndex: String,
    pub r#type: String, // `type` is a reserved keyword, so use `r#type`
    pub v: String,
    pub value: String,
    pub yParity: String,
}


impl EvmRpcCanister {
    pub async fn eth_get_transaction_by_hash(
        custom_service: RpcApi, 
        tx_hash: String,
        cycles: u128,
    ) -> CallResult<String> {
        // Build JSON-RPC request
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "eth_getTransactionByHash".to_string(),
            params: vec![tx_hash], // Parameters in JSON-RPC format
            id: 1,
        };

        // Serialize the request to JSON
        let request_json = serde_json::to_string(&request).map_err(|e| {
            ic_cdk::trap(&format!("Failed to serialize JSON-RPC request: {}", e));
        })?;

        let rpc_service = RpcService::Custom(custom_service);

        // Perform the canister call
        let result: CallResult<(RequestResult,)> = ic_cdk::api::call::call_with_payment128(
            CANISTER_ID,                  // The canister ID for the RPC canister
            "request",                    // The method to invoke
            (rpc_service, request_json, 5000_u64), // Pass the rpc_service and JSON request
            cycles,
        )
        .await;

        // Handle the response
        match result {
            Ok((RequestResult::Ok(response_json),)) => Ok(response_json),
            Ok((RequestResult::Err(err),)) => Err((
                ic_cdk::api::call::RejectionCode::CanisterError,
                format!("{:?}", err),
            )),
            Err(e) => Err(e),
        }
    }
}

// Thread-local storage for canister state
thread_local! {
    static STATE: RefCell<CanisterState> = RefCell::new(CanisterState::new());
}

// Helper functions to interact with state
fn with_state<R>(f: impl FnOnce(&mut CanisterState) -> R) -> R {
    STATE.with(|state| f(&mut state.borrow_mut()))
}

//TODO: state functions to come





fn parse_transaction_response(response: &str) -> Result<TransactionResult, serde_json::Error> {
    serde_json::from_str::<TransactionResult>(response)
}

fn decode_erc20_transfer(input: &str) -> Option<(String, u128)> {
    if input.len() < 138 || &input[0..10] != "0xa9059cbb" {
        return None; // Not an ERC20 transfer
    }

    // Extract recipient address (bytes 4-36) and amount (bytes 36-68)
    let recipient = format!("0x{}", &input[34..74]);
    let amount = u128::from_str_radix(&input[74..138], 16).ok()?; // Convert hex to u128

    Some((recipient, amount))
}

fn handle_transaction_response(raw_response: &str) -> Result<String, String> {
    // Parse the JSON response
    let transaction_result: TransactionResult = parse_transaction_response(raw_response)
        .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

    let details = transaction_result.result;

    // Log the parsed transaction details
    println!("Parsed Transaction Details: {:?}", details);

    // Decode the ERC20 transfer (if applicable)
    if let Some((recipient, amount)) = decode_erc20_transfer(&details.input) {
        Ok(format!(
            "ERC20 Transfer:\nRecipient: {}\nAmount: {}",
            recipient, amount
        ))
    } else {
        Ok("Not an ERC20 transfer".to_string())
    }
}


/* 

fn parse_erc20_transfer(input: &str) -> Option<(String, u128)> {
    // Ensure input starts with the expected function selector for `transfer`
    if input.len() < 138 || &input[0..10] != "0xa9059cbb" {
        return None;
    }

    // Extract recipient address and amount
    let recipient = format!("0x{}", &input[34..74]); // 32 bytes after the selector
    let amount = u128::from_str_radix(&input[74..138], 16).ok()?; // Last 32 bytes

    Some((recipient, amount))
}
    */

#[ic_cdk::update]
async fn get_transaction_details(tx_hash: String) -> String {
    let rpc_api = RpcApi {
        url: "https://api.avax.network/ext/bc/C/rpc".to_string(),
        headers: None,
    };

    match EvmRpcCanister::eth_get_transaction_by_hash(rpc_api, tx_hash, 25_000_000_000).await {
        Ok(response) => {
            match handle_transaction_response(&response) {
                Ok(result) => {
                    result                    
                },
                Err(err) => format!("Error handling transaction response: {}", err),
            }
        },
        Err((code, err)) => format!("Error fetching transaction: {:?}, {}", code, err),
    }
}

