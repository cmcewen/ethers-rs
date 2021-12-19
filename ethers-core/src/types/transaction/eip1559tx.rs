use super::{eip2930::AccessList};
use crate::{
    types::{Address, H256, U256, U64},
    utils::keccak256,
};
use rlp::{encode};
use rlp_derive::{RlpEncodable, RlpDecodable};
use bytes::Bytes;

use serde::{Deserialize, Serialize};
/// Parameters for sending a transaction
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug, RlpEncodable, RlpDecodable)]
pub struct UnsignedEip1559Transaction {
    /// Chain Id
    pub chain_id: U256,

    /// Transaction nonce
    pub nonce: U256,

    #[serde(rename = "maxPriorityFeePerGas", default)]
    /// Represents the maximum tx fee that will go to the miner as part of the user's
    /// fee payment. It serves 3 purposes:
    /// 1. Compensates miners for the uncle/ommer risk + fixed costs of including transaction in a
    /// block; 2. Allows users with high opportunity costs to pay a premium to miners;
    /// 3. In times where demand exceeds the available block space (i.e. 100% full, 30mm gas),
    /// this component allows first price auctions (i.e. the pre-1559 fee model) to happen on the
    /// priority fee.
    ///
    /// More context [here](https://hackmd.io/@q8X_WM2nTfu6nuvAzqXiTQ/1559-wallets)
    pub max_priority_fee_per_gas: U256,

    #[serde(rename = "maxFeePerGas", default)]
    /// Represents the maximum amount that a user is willing to pay for their tx (inclusive of
    /// baseFeePerGas and maxPriorityFeePerGas). The difference between maxFeePerGas and
    /// baseFeePerGas + maxPriorityFeePerGas is “refunded” to the user.
    pub max_fee_per_gas: U256,

    /// Supplied gas (None for sensible default)
    pub gas: U256,

    /// Recipient address (None for contract creation)
    pub to: Address,

    /// Transfered value (None for no transfer)
    pub value: U256,

    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    pub data: Bytes,

    #[serde(rename = "accessList", default)]
    pub access_list: AccessList,
}

impl UnsignedEip1559Transaction {
    /// Hashes the transaction's data
    pub fn sighash<T: Into<U64>>(&self) -> H256 {
        keccak256(encode(self).as_ref()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn rlp_encode() {
        let tx = UnsignedEip1559Transaction {
            chain_id: U256::from_dec_str("1").unwrap(),
            gas: U256::from_dec_str("1").unwrap(),
            data: Bytes::from(hex::decode("a9059cbb000000000000000000000000fdae129ecc2c27d166a3131098bc05d143fa258e0000000000000000000000000000000000000000000000000000000002faf080").unwrap().to_vec()),
            nonce: U256::from_dec_str("1").unwrap(),
            to: Address::from_str("dAC17F958D2ee523a2206206994597C13D831ec7").unwrap(),
            value: U256::from_dec_str("1").unwrap(),
            access_list: AccessList::from(vec![]),
            max_fee_per_gas: U256::from_dec_str("1").unwrap(),
            max_priority_fee_per_gas: U256::from_dec_str("1").unwrap()
        };
        let enc = rlp::encode(&tx).freeze();
        let hexnum = hex::decode("f862010101010194dac17f958d2ee523a2206206994597c13d831ec701b844a9059cbb000000000000000000000000fdae129ecc2c27d166a3131098bc05d143fa258e0000000000000000000000000000000000000000000000000000000002faf080c0").unwrap();
        assert_eq!(
            enc,
            Bytes::from(hexnum)
        )
    }

    #[test]
    fn rlp_decode() {
        let tx = UnsignedEip1559Transaction {
            chain_id: U256::from_dec_str("1").unwrap(),
            gas: U256::from_dec_str("1").unwrap(),
            data: Bytes::from(hex::decode("a9059cbb000000000000000000000000fdae129ecc2c27d166a3131098bc05d143fa258e0000000000000000000000000000000000000000000000000000000002faf080").unwrap().to_vec()),
            nonce: U256::from_dec_str("1").unwrap(),
            to: Address::from_str("dAC17F958D2ee523a2206206994597C13D831ec7").unwrap(),
            value: U256::from_dec_str("1").unwrap(),
            access_list: AccessList::from(vec![]),
            max_fee_per_gas: U256::from_dec_str("1").unwrap(),
            max_priority_fee_per_gas: U256::from_dec_str("1").unwrap()
        };
        let hexnum = hex::decode("f862010101010194dac17f958d2ee523a2206206994597c13d831ec701b844a9059cbb000000000000000000000000fdae129ecc2c27d166a3131098bc05d143fa258e0000000000000000000000000000000000000000000000000000000002faf080c0").unwrap();
        let decoded_tx: UnsignedEip1559Transaction = rlp::decode(&hexnum.to_vec()).unwrap();
        assert_eq!(
            tx,
            decoded_tx
        )
    }
}