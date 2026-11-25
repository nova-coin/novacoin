// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "bitcoinrpc.h"
#include "interface.h"
#include "base58.h"
#include "wallet.h"

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

void EnsureWalletIsUnlocked();

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64_t nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey <novacoinprivkey> [label] [rescan=true]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    if (fWalletUnlockMintOnly) // ppcoin: no importprivkey in mint-only mode
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID keyid = key.GetPubKey().GetID();
    CBitcoinAddress addr = CBitcoinAddress(keyid);
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(keyid))
            return Value::null;

        pwalletMain->mapKeyMetadata[addr].nCreateTime = 1;
        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(addr, strLabel);

        if (fRescan)
        {
            // whenever a key is imported, we need to scan the whole chain
            pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value importfalconkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importfalconkey <falconkey> [label] [rescan=true]\n"
            "Adds a falcon-512 (post-quantum) key pair (as returned by dumpfalconkey) to your wallet\n"
            "and restores the falcon address it backed.");

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    if (fWalletUnlockMintOnly) // ppcoin: no importfalconkey in mint-only mode
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CBitcoinFalconKey falconSecret;
    if (!falconSecret.SetString(strSecret))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
            strprintf("Invalid falcon key encoding (decoded version byte %d, this wallet expects %d; "
                      "version 0 means invalid base58 or broken checksum - check the key was copied in full, "
                      "without spaces or line breaks)",
                      falconSecret.GetVersion(),
                      fTestNet ? 250 : 128 + CBitcoinAddress::SCRIPT_ADDRESS));

    CFalconKey key;
    if (!falconSecret.GetKey(key) || !key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid falcon private key");

    std::vector<unsigned char> vchSalt;
    if (!falconSecret.GetSalt(vchSalt))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid falcon private key");

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        // Rebuild the original redeem script so the imported address matches the exported one
        std::vector<unsigned char> vchScript;
        CFalconKey::BuildRedeemScript(vchSalt, key.GetID(), vchScript);
        CScript redeemScript(vchScript.begin(), vchScript.end());
        CScriptID scriptID(redeemScript.GetID());
        CBitcoinAddress addr(scriptID);

        // Don't throw error in case a key is already there
        if (!pwalletMain->HaveFalconKey(key.GetID()) && !pwalletMain->AddFalconKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        if (!pwalletMain->HaveCScript(scriptID) && !pwalletMain->AddCScript(redeemScript))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding script to wallet");

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(addr, strLabel);

        if (fRescan)
        {
            // whenever a key is imported, we need to scan the whole chain
            pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

        return addr.ToString();
    }
}

Value importaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importaddress <address> [label] [rescan=true]\n"
            "Adds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.");

    CScript script;
    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (address.IsPair())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "It's senseless to import pubkey pair address.");
        script.SetAddress(address);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Novacoin address or script");

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        if (::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
            throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

        // Don't throw error in case an address is already there
        if (pwalletMain->HaveWatchOnly(script))
            return Value::null;

        pwalletMain->MarkDirty();

        if (address.IsValid())
            pwalletMain->SetAddressBookName(address, strLabel);

        if (!pwalletMain->AddWatchOnly(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

        if (fRescan)
        {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value removeaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "removeaddress 'address'\n"
            "\nRemoves watch-only address or script (in hex) added by importaddress.\n"
            "\nArguments:\n"
            "1. 'address' (string, required) The address\n"
            "\nExamples:\n"
            "\nremoveaddress 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n"
            "\nRemove watch-only address 4EqHMPgEAf56CQmU6ZWS8Ug4d7N3gsQVQA\n");

    CScript script;

    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        if (address.IsPair())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pubkey pair addresses aren't supported.");
        script.SetAddress(address);
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");

    if (::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet contains the private key for this address or script - can't remove it");

    if (!pwalletMain->HaveWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "The wallet does not contain this address or script");

    LOCK2(cs_main, pwalletMain->cs_wallet);

    pwalletMain->MarkDirty();

    if (!pwalletMain->RemoveWatchOnly(script))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error removing address from wallet");

    return Value::null;
}

Value importwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet <filename>\n"
            "Imports keys from a wallet dump file (see dumpwallet)."
            + HelpRequiringPassphrase());

    EnsureWalletIsUnlocked();

    if(!ImportWallet(pwalletMain, params[0].get_str().c_str()))
       throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <novacoinaddress>\n"
            "Reveals the private key corresponding to <novacoinaddress>.");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid NovaCoin address");
    if (fWalletUnlockMintOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}

Value dumpwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpwallet <filename>\n"
            "Dumps all wallet keys in a human-readable format."
            + HelpRequiringPassphrase());

    EnsureWalletIsUnlocked();

    if(!DumpWallet(pwalletMain, params[0].get_str().c_str() ))
      throw JSONRPCError(RPC_WALLET_ERROR, "Error dumping wallet keys to file");

    return Value::null;
}

Value dumpfalconkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpfalconkey <novacoinaddress>\n"
            "Reveals the falcon-512 (post-quantum) key pair corresponding to <novacoinaddress>.\n"
            "The redeem script salt is embedded, so importfalconkey in another wallet\n"
            "reproduces the same address.");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid NovaCoin address");
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid NovaCoin address");
    if (fWalletUnlockMintOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is unlocked for minting only.");

    CTxDestination dest = address.Get();
    const CScriptID *pScriptID = std::get_if<CScriptID>(&dest);
    if (!pScriptID)
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a falcon key");

    CScript redeemScript;
    if (!pwalletMain->GetCScript(*pScriptID, redeemScript))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    txnouttype whichType;
    std::vector<std::vector<unsigned char> > vSolutions;
    Solver(redeemScript, whichType, vSolutions);
    if (whichType != TX_FALCON)
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not commit to a falcon key");

    CFalconKeyID keyID = CFalconKeyID(uint256(vSolutions[0]));
    CFalconKey key;
    if (!pwalletMain->GetFalconKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    // Extract the 16-byte salt from the redeem script so the imported key
    // reproduces the same address in another wallet
    opcodetype opcode;
    std::vector<unsigned char> vchOp;
    CScript::const_iterator itScript = redeemScript.begin();
    if (!redeemScript.GetOp(itScript, opcode, vchOp) || opcode != 16 || vchOp.size() != CBitcoinFalconKey::SALT_SIZE)
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot extract salt from redeem script");

    return CBitcoinFalconKey(key, vchOp).ToString();
}

Value dumpmalleablekey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error (
            "dumpmalleablekey <Key view>\n"
            "Dump the private and public key pairs, which correspond to provided key view.\n");

    EnsureWalletIsUnlocked();

    CMalleableKey mKey;
    CMalleableKeyView keyView;
    keyView.SetString(params[0].get_str());

    if (!pwalletMain->GetMalleableKey(keyView, mKey))
        throw runtime_error("There is no such item in the wallet");

    Object result;
    result.push_back(Pair("PrivatePair", mKey.ToString()));
    result.push_back(Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));

    return result;
}

Value importmalleablekey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error (
            "importmalleablekey <Key data>\n"
            "Imports the private key pair into your wallet.\n");


    EnsureWalletIsUnlocked();

    CMalleableKey mKey;
    bool fSuccess = mKey.SetString(params[0].get_str());

    Object result;

    if (fSuccess)
    {
        fSuccess = pwalletMain->AddKey(mKey);
        result.push_back(Pair("Successful", fSuccess));
        result.push_back(Pair("Address", CBitcoinAddress(mKey.GetMalleablePubKey()).ToString()));
        result.push_back(Pair("KeyView", CMalleableKeyView(mKey).ToString()));
    }
    else
        result.push_back(Pair("Successful", false));

    return result;
}
