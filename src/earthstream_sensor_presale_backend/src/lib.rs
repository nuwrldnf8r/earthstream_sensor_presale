#![allow(non_snake_case)]
mod evm_rpc;
use evm_rpc::{
    RpcApi, EvmRpcCanister, RpcService, RequestResult, CANISTER_ID
};
use ic_cdk::{self, api::call::CallResult};
use candid::{CandidType};
use serde::{Deserialize, Serialize};
use std::string::String;
use candid::Principal;
use std::collections::HashMap;
use std::cell::RefCell;
use sha2::{Sha256, Digest};
use ic_cdk_macros::*;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Transaction {
    pub chain_id: String, // BigUint64Array equivalent
    pub txhash: String,
    pub token_type: TokenType,
    pub contract_address: String,
    pub amount: u64, // Amount in wei
    pub from_address: String,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Sensor {
    pub sensor_id: String,
    pub public_key: String,
    pub sensor_type: SensorType,
    pub owner: Principal,
    pub assign_type: AssignType,
    pub project_id: Option<String>,
    pub purchase_date: Option<u64>, // Timestamp in seconds
    pub txhash: String, // Reference to transaction
    pub status: SensorStatus,
}


#[derive(Clone, Debug, CandidType, Deserialize,PartialEq, Eq, Hash)]
pub enum SensorType {
    Gsm,
    Lora,
    GatewayGsm,
    GatewayWifi,
}

#[derive(Clone, Debug, CandidType, Deserialize,PartialEq, Eq, Hash)]
pub enum AssignType {
    OWNER,
    PROJECT,
}

#[derive(Clone, Debug, CandidType, Deserialize,PartialEq, Eq, Hash)]
pub enum SensorStatus {
    Presale,
    ProcessingForshipping,
    Shipped,
    Deployed,
    Offline,
    Query,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct User {
    pub user_principal: Principal,
    pub address: String, // EVM address
    pub discord_handle: String,
}

#[derive(Clone, Debug, CandidType, Deserialize,PartialEq, Eq, Hash)]
pub enum TokenType {
    Native,
    Erc20,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct AcceptedToken {
    pub token_id: String,
    pub chain_id: String, // BigUint64Array equivalent
    pub rpc_url: String,
    pub token_type: TokenType,
    pub contract_address: Option<String>, // Optional for NATIVE tokens
    pub symbol: String,
    pub decimals: u8,
    pub sensor_base_price: u64, // Price in wei
    pub receive_address: String, // EVM address
}


// Canister state
#[derive(Default)]
struct CanisterState {
    pub sensors: HashMap<String, Sensor>,
    pub users: HashMap<Principal, User>,
    pub transactions: HashMap<String, Transaction>, // Store transactions by txhash
    pub accepted_tokens: Vec<AcceptedToken>, // Store accepted tokens centrally
    pub price_ratios: HashMap<SensorType, u64>,
    pub admins: Vec<Principal>,
    pub super_admin: Option<Principal>,
}


// Canister logic skeleton
impl CanisterState {
    pub fn new() -> Self {
        Self {
            sensors: HashMap::new(),
            users: HashMap::new(),
            transactions: HashMap::new(),
            accepted_tokens: Vec::new(),
            price_ratios: HashMap::new(),
            admins: Vec::new(),
            super_admin: None,
        }
    }
    // Admin functions
    pub fn create_super_admin(&mut self, caller: Principal) -> Result<(), String> {
        if self.super_admin.is_none() {
            self.super_admin = Some(caller);
            Ok(())
        } else if self.super_admin == Some(caller) {
            Err("Super admin already exists.".to_string())
        } else {
            Err("Permission denied.".to_string())
        }
    }

    pub fn add_admin(&mut self, caller: Principal, new_admin: Principal) -> Result<(), String> {
        if self.super_admin == Some(caller) {
            if !self.admins.contains(&new_admin) {
                self.admins.push(new_admin);
            }
            Ok(())
        } else {
            Err("Permission denied.".to_string())
        }
    }

    pub fn remove_admin(&mut self, caller: Principal, admin: Principal) -> Result<(), String> {
        if self.super_admin == Some(caller) {
            self.admins.retain(|&x| x != admin);
            Ok(())
        } else {
            Err("Permission denied.".to_string())
        }
    }

    
    pub fn add_user(
        &mut self,
        caller: Principal,
        address: String,
        discord_handle: String,
    ) -> Result<(), String> {
        // Check if the user already exists
        if self.users.contains_key(&caller) {
            return Err("User already exists.".to_string());
        }

        // Add the new user
        let user = User {
            user_principal: caller,
            address,
            discord_handle,
        };
        self.users.insert(caller, user);
        Ok(())
    }

    pub fn edit_user(
        &mut self,
        caller: Principal,
        user_principal: Principal,
        new_address: Option<String>,
        new_discord_handle: Option<String>,
    ) -> Result<(), String> {
        // Check if the user exists
        if let Some(user) = self.users.get_mut(&user_principal) {
            // Check if the caller is the user or an admin
            if caller != user_principal
                && !self.admins.contains(&caller)
                && self.super_admin != Some(caller)
            {
                return Err("Permission denied.".to_string());
            }

            // Update the user's information
            if let Some(address) = new_address {
                user.address = address;
            }
            if let Some(discord_handle) = new_discord_handle {
                user.discord_handle = discord_handle;
            }

            Ok(())
        } else {
            Err("User not found.".to_string())
        }
    }
    
    pub fn get_user(&self, principal: Principal) -> Result<&User, String> {
        self.users.get(&principal).ok_or_else(|| "User not found.".to_string())
    }

    /*
    pub fn get_transaction(&self, txhash: &str) -> Option<Transaction> {
        self.transactions.get(txhash)
    }

    pub fn list_transactions(&self) -> Vec<Transaction> {
        self.transactions.values().collect()
    }
    */

    pub fn purchase_sensor(
        &mut self,
        sensor_type: SensorType,
        chain_id: String,
        txhash: String,
        caller: Principal,
        amount: u64,
        token_type: TokenType,
        contract_address: String,
        from_address: String,
        sensor_number: u64,
    ) -> Result<Vec<String>, String> {
        // Check if the transaction already exists
        if self.transactions.contains_key(&txhash) {
            return Err("Transaction already exists.".to_string());
        }
    
        // Add the transaction
        let transaction = Transaction {
            chain_id,
            txhash: txhash.clone(),
            token_type,
            contract_address: contract_address.clone(),
            amount,
            from_address: from_address.clone(),
        };
        self.transactions.insert(txhash.clone(), transaction);
    
        // Create sensors
        let mut sensor_ids = Vec::new();
        for i in 0..sensor_number {
            let mut hasher = Sha256::new();
            hasher.update(&txhash);
            hasher.update(&caller.as_slice());
            hasher.update(&amount.to_le_bytes());
            hasher.update(&contract_address);
            hasher.update(&from_address);
            hasher.update(&i.to_le_bytes());
            let sensor_id = hex::encode(hasher.finalize()); // Generate unique sensor ID
    
            // Check if the sensor ID already exists
            if self.sensors.contains_key(&sensor_id) {
                return Err(format!("Sensor ID {} already exists.", sensor_id));
            }
    
            // Add the sensor
            let new_sensor = Sensor {
                sensor_id: sensor_id.clone(),
                public_key: String::new(), // Will be provisioned later
                sensor_type: sensor_type.clone(),
                owner: caller.clone(),
                assign_type: AssignType::OWNER,
                project_id: None,
                purchase_date: Some(ic_cdk::api::time() / 1_000_000), // Convert from nanoseconds to seconds
                txhash: txhash.clone(), // Link to transaction
                status: SensorStatus::Presale,
            };
            self.sensors.insert(sensor_id.clone(), new_sensor);
            sensor_ids.push(sensor_id);
        }
    
        Ok(sensor_ids)
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
    
    pub fn count_sensors(&self) -> usize {
        self.sensors.len()
    }

    // Sensor functions
    pub fn edit_sensor_status(
        &mut self,
        caller: Principal,
        sensor_id: &str,
        new_status: SensorStatus,
    ) -> Result<(), String> {
        if self.admins.contains(&caller) || self.super_admin == Some(caller) {
            if let Some(sensor) = self.sensors.get_mut(sensor_id) {
                sensor.status = new_status;
                Ok(())
            } else {
                Err("Sensor not found.".to_string())
            }
        } else {
            Err("Permission denied.".to_string())
        }
    }

    pub fn set_sensor_project_id(
        &mut self,
        caller: Principal,
        sensor_id: &str,
        project_id: String,
    ) -> Result<(), String> {
        if let Some(sensor) = self.sensors.get_mut(sensor_id) {
            if sensor.owner == caller {
                if sensor.project_id.is_none() {
                    sensor.project_id = Some(project_id);
                    Ok(())
                } else {
                    Err("Project ID is already set.".to_string())
                }
            } else {
                Err("Permission denied.".to_string())
            }
        } else {
            Err("Sensor not found.".to_string())
        }
    }

    pub fn remove_sensor_project_id(&mut self, caller: Principal, sensor_id: &str) -> Result<(), String> {
        if self.admins.contains(&caller) || self.super_admin == Some(caller) {
            if let Some(sensor) = self.sensors.get_mut(sensor_id) {
                sensor.project_id = None;
                Ok(())
            } else {
                Err("Sensor not found.".to_string())
            }
        } else {
            Err("Permission denied.".to_string())
        }
    }

    pub fn add_accepted_token(
        &mut self,
        caller: Principal,
        token: AcceptedToken,
    ) -> Result<(), String> {
        if self.admins.contains(&caller) || self.super_admin == Some(caller) {
            // Ensure the token doesn't already exist
            if self.accepted_tokens.iter().any(|t| t.token_id == token.token_id) {
                return Err("Token already exists.".to_string());
            }
            self.accepted_tokens.push(token);
            Ok(())
        } else {
            Err("Permission denied.".to_string())
        }
    }

    pub fn remove_accepted_token(&mut self, caller: Principal, token_id: &str) -> Result<(), String> {
        if self.admins.contains(&caller) || self.super_admin == Some(caller) {
            let original_len = self.accepted_tokens.len();
            self.accepted_tokens.retain(|token| token.token_id != token_id);
            if self.accepted_tokens.len() < original_len {
                Ok(())
            } else {
                Err("Token not found.".to_string())
            }
        } else {
            Err("Permission denied.".to_string())
        }
    }
    
    pub fn get_accepted_token(
        &self,
        token_id: &str,
    ) -> Option<&AcceptedToken> {
        self.accepted_tokens.iter().find(|token| {
            token.token_id == token_id
        })
    }
    
    pub fn list_accepted_tokens(
        &self,
        chain_id: Option<&str>,
        token_type: Option<&TokenType>,
    ) -> Vec<AcceptedToken> {
        self.accepted_tokens
            .iter()
            .filter(|token| {
                (chain_id.is_none() || token.chain_id == chain_id.unwrap())
                    && (token_type.is_none() || token.token_type == *token_type.unwrap())
            })
            .cloned() // Clone each `AcceptedToken` to return owned values
            .collect()
    }
    
       

    pub fn set_price_ratio(
        &mut self,
        caller: Principal,
        sensor_type: SensorType,
        price_ratio: u64
    ) -> Result<(), String> {
        if self.admins.contains(&caller) || self.super_admin == Some(caller) {
            if let Some(ratio) = self.price_ratios.get_mut(&sensor_type) {
                *ratio = price_ratio;
            } else {
                self.price_ratios.insert(sensor_type, price_ratio);
            }
            Ok(())
        } else {
            Err("Permission denied.".to_string())
        } 
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


//chain fusion stuff
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

async fn validate_erc20(rpc_url: String, tx_hash: String, from: String, to: String, amount: u128) -> Result<String, String> {
    let rpc_api = RpcApi {
        url: rpc_url,
        headers: None,
    };

    match EvmRpcCanister::eth_get_transaction_by_hash(rpc_api, tx_hash, 25_000_000_000).await {
        Ok(response) => {
            let transaction_result: TransactionResult = parse_transaction_response(&response)
                    .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

            let details = transaction_result.result;
            let from_ = details.from.clone();
            // Decode the ERC20 transfer (if applicable)
            if let Some((recipient, amount_)) = decode_erc20_transfer(&details.input) {
                if recipient.to_lowercase() != to.to_lowercase(){
                    return Err(format!("Invalid Recipient: {}", recipient));
                }
                if from.to_lowercase() != from_.to_lowercase() {
                    return Err(format!("Invalid Sender: {}", from));
                }
                if amount != amount_ {
                    return Err(format!("Invalid Amount: {}", amount));
                }
                return Ok(format!(
                    "ERC20 Transfer:\nRecipient: {}, From: {}, Amount: {}",
                    recipient, from, amount
                ));

            } else {
                Err("Not an ERC20 transfer".to_string())
            }
        },
        Err((code, err)) => Err(format!("Error fetching transaction: {:?}, {}", code, err)),
    }
}

async fn validate_native(rpc_url: String, tx_hash: String, from: String, to: String, amount: u128) -> Result<String, String> {
    let rpc_api = RpcApi {
        url: rpc_url,
        headers: None,
    };

    match EvmRpcCanister::eth_get_transaction_by_hash(rpc_api, tx_hash, 25_000_000_000).await {
        Ok(response) => {
            let transaction_result: TransactionResult = parse_transaction_response(&response)
                    .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

            let details = transaction_result.result;
            let from_ = details.from.clone();
            let value = details.value.clone();
            let to_ = details.to.clone();

            let value = u128::from_str_radix(value.trim_start_matches("0x"), 16)
                .map_err(|e| format!("Invalid value: {}", e))?;
            
            if to.to_lowercase() != to_.to_lowercase(){
                return Err(format!("Invalid Recipient: {}", to_));
            }
            if from.to_lowercase() != from_.to_lowercase() {
                return Err(format!("Invalid Sender: {}", from));
            }
            if amount != value {
                return Err(format!("Invalid Amount: {}", amount));
            }
            return Ok(format!(
                "Native Send:\nRecipient: {}, From: {}, Amount: {}",
                to_, from, amount
            ));

            
        },
        Err((code, err)) => Err(format!("Error fetching transaction: {:?}, {}", code, err)),
    }
}

//public functions:
#[query]
fn list_accepted_tokens(
    chain_id: Option<String>,       
    token_type: Option<TokenType>, 
) -> Vec<AcceptedToken> {
    with_state(|state| {
        state.list_accepted_tokens(
            chain_id.as_deref(), 
            token_type.as_ref(),
        )
    })
}


#[update]
async fn set_price_ratio(
    sensor_type: SensorType,
    price_ratio: u64
) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.set_price_ratio(caller, sensor_type, price_ratio))
}

#[update]
async fn add_accepted_token(
    token: AcceptedToken,
) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.add_accepted_token(caller, token))
}

#[update]
async fn remove_accepted_token(caller: Principal, token_id: String) -> Result<(), String> {
    with_state(|state| state.remove_accepted_token(caller, &token_id))
}


fn get_price(
    sensor_type: SensorType, // Owned type
    token_id: String,        // Owned type
    amount: u64,
) -> Result<u128, String> {
    with_state(|state| {
        if let Some(token) = state.get_accepted_token(&token_id) {
            let price_ratio = state
                .price_ratios
                .get(&sensor_type)
                .ok_or("Price ratio not set.")?;

            // Use u128 for intermediate calculations to avoid overflow
            let amount = amount as u128;
            let sensor_base_price = token.sensor_base_price as u128;
            let price_ratio = price_ratio.clone();
            let price_ratio = price_ratio as u128;
            let decimals = power(10, token.decimals) as u128;

            let total_price = amount * (sensor_base_price * price_ratio)/100 * decimals/10; //should be /100 but for some reason the amount is *10 more than it should be

            // Convert back to u64 if it fits
            total_price.try_into().map_err(|_| "Price exceeds u64 capacity".to_string())
        } else {
            Err("Token not found.".to_string())
        }
    })
}

#[query]
fn get_formatted_price(
    sensor_type: SensorType,
    token_id: String,
    amount: u64,
) -> Result<String, String> {
    get_price(sensor_type, token_id, amount)
        .map(|price| {
            format!("{} wei", price)
        })
}

// Adjusted power function
fn power(base: u64, exponent: u8) -> u64 {
    base.checked_pow(exponent.into())
        .unwrap_or_else(|| panic!("Exponentiation overflow for base: {} and exponent: {}", base, exponent))
}


#[query]
fn get_token(token_id: String) -> Result<AcceptedToken, String> {
    with_state(|state| {
        let t = state.get_accepted_token(token_id.as_str());
        t.cloned().ok_or("Token not found.".to_string())
    })
}

#[update]
async fn purchase_sensor(
    sensor_type: SensorType,
    token_id: String,
    txhash: String,
    from_address: String,
    sensor_count: u64,
) -> Result<Vec<String>, String> {
    let caller = ic_cdk::api::caller();
    let token = get_token(token_id.clone()).map_err(|_| "No token found".to_string())?;
    let rpc_url = token.rpc_url.clone();
    let token_type = token.token_type.clone();
    let contract_address = token.contract_address.clone().unwrap_or("none".to_string());
    let receive_address = token.receive_address.clone();
    let chain_id = token.chain_id.clone();
    let amount = token.sensor_base_price.clone();

    // Calculate the required price
    let num_sensors: u128 = sensor_count.into();
    let total_price = get_price(sensor_type.clone(), token_id, amount)
        .map_err(|err| format!("Invalid price: {}", err))? * num_sensors;

    // Validate transaction based on token type
    let validation_result = if token_type == TokenType::Erc20 {
        //TODO: need to validate on contract address as well
        validate_erc20(rpc_url, txhash.clone(), from_address.clone(), receive_address, total_price).await
    } else {
        validate_native(rpc_url, txhash.clone(), from_address.clone(), receive_address, total_price).await
    };

    validation_result.map_err(|err| format!("Transaction validation failed: {}", err))?;

    // Record transaction and add sensors
    with_state(|state| {
        state.purchase_sensor(
            sensor_type, chain_id, txhash, caller, amount, token_type, contract_address, from_address, sensor_count,
        )
    })
}

#[query]
fn count_sensors() -> usize {
    with_state(|state| state.count_sensors())
}

#[query]
fn list_sensors_by_owner(owner: Principal) -> Vec<Sensor> {
    with_state(|state| state.list_sensors_by_owner(owner))
}

#[query]
fn list_sensors_by_project(project_id: String) -> Vec<Sensor> {
    with_state(|state| state.list_sensors_by_project(project_id))
}

#[query]
fn list_sensors_by_type_and_date(
    sensor_type: SensorType,
    start_date: u64,
    end_date: u64,
) -> Vec<Sensor> {
    with_state(|state| state.list_sensors_by_type_and_date(sensor_type, start_date, end_date))
}


#[update]
async fn edit_sensor_status(
    sensor_id: String,
    new_status: SensorStatus,
) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.edit_sensor_status(caller, &sensor_id, new_status))
}

#[update]
async fn set_sensor_project_id(
    sensor_id: String,
    project_id: String,
) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.set_sensor_project_id(caller, &sensor_id, project_id))
}

#[update]
fn remove_sensor_project_id(sensor_id: String) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.remove_sensor_project_id(caller, &sensor_id))
}

#[update]
async fn create_super_admin() -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.create_super_admin(caller))
}

#[update]
async fn add_admin(new_admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.add_admin(caller, new_admin))
}

#[update]
async fn remove_admin(admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.remove_admin(caller, admin))
}

#[update]
async fn add_user(
    address: String,
    discord_handle: String,
) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| state.add_user(caller, address, discord_handle))
}

#[update]
async fn edit_user(
    user_principal: Principal,
    new_address: Option<String>,
    new_discord_handle: Option<String>,
) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    with_state(|state| {
        state.edit_user(caller, user_principal, new_address, new_discord_handle)
    })
}

#[query]
fn get_user(principal: Principal) -> Result<User, String> {
    with_state(|state| state.get_user(principal).cloned())
}



    








