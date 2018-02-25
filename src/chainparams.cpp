
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=4e9b54001f9976049830128ec0331515eaabe35a70970d79971da1539a400ba1, PoW=000001a16729477595c7247e1b49b4ec93acca8345037177cabbe898ce8a5783, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000,
 *     hashMerkleRoot=0317d32e01a2adf6f2ac6f58c7cdaab6c656edc6fdb45986c739290053275200,
 *     nTime=1405164774, nBits=1e01ffff, nNonce=4016033, vtx=1)
 *   CTransaction(hash=0317d32e01, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *   CTxIn(COutPoint(0000000000, 4294967295), coinbase 04ffff001d01044c4e426c6f636b20233331303337393a30303030303030303030303030303030323431323532613762623237626539376265666539323138633132393064666633366331666631323965633732313161)
 *   CTxOut(nValue=0.00000000, scriptPubKey=0459934a6a228ce9716fa0b13aa1cd)
 * vMerkleTree: 0317d32e01a2adf6f2ac6f58c7cdaab6c656edc6fdb45986c739290053275200
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "China Hits Qualcomm With Fine - NY Times Monday, February 9, 2015";
    const CScript genesisOutputScript = CScript() << ParseHex("04244ee84fdded7f915fbbba099b2f1ee814dfebfe7036ba5d1101684ca692aa18bb7446fbc529e3d8f5f51cc3c4d8378b9b570d6291f0a0b26e170a4be602c6c1") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 25600000;
        consensus.nMajorityEnforceBlockUpgrade = 15000;
        consensus.nMajorityRejectBlockOutdated = 19000;
        consensus.nMajorityWindow = 20000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.BIP65Height = 76;
        consensus.BIP66Height = 76;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint25(0) >> 23
        consensus.nPowTargetTimespan = 120; // 2 mins
        consensus.nPowTargetSpacing = 60; // 1 min
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7560; // 75% of nMinerConfirmationWindow
        consensus.nMinerConfirmationWindow = 10080; // 1 week
        consensus.nCLTVStartBlock = 1100000;
        consensus.nBIP66MinStartBlock = 1200000;
        consensus.nAuxPowStartHeight = AuxPow::START_MAINNET;
        consensus.nWitnessStartHeight = 4040000;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1232032894; // start + (1year/25)

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1519276440; // February 22, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1550812597;   // February 22, 2019

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1519276440 ; // February 22, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1550812597 ;   // February 22, 2019

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000364b0cbc3568");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xc0;
        nDefaultPort = 7300;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1423553425, 1078456, 0x1e0ffff0, 1, 17500 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8753b01bc2dafef2973a1378eb9465617893da73ac177e5ed376f05f42c2a820"));
        assert(genesis.hashMerkleRoot == uint256S("0x16733a25293a66a2d0a304ee04ef55f8e7fff7d441efad46d840592d8de89028"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        // TODO - LED - Check which experiencecoin nodes support service bits and add the 'true' flag
        vSeeds.push_back(CDNSSeedData("lon.epcnodes.com", "lon.epcnodes.com"));
        vSeeds.push_back(CDNSSeedData("ny.epcnodes.com", "ny.epcnodes.com"));


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,33);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,78);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,176);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  968600, uint256S("0x7653d4971420ed27905d1c59d1f8e9abf5b15364edeb0de4f2a87232677d0464"))
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 657000;
        consensus.nMajorityEnforceBlockUpgrade = 510;
        consensus.nMajorityRejectBlockOutdated = 750;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint25(0) >> 19
        consensus.nPowTargetTimespan = 120; // 2 mins
        consensus.nPowTargetSpacing = 60; // 1 min
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 7560; // 75% of nMinerConfirmationWindow
        consensus.nMinerConfirmationWindow = 10080; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nCLTVStartBlock = 502664;
        consensus.nBIP66MinStartBlock = 800000;
        consensus.nAuxPowStartHeight = AuxPow::START_TESTNET;
        consensus.nWitnessStartHeight = 4040000;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1232032894; // start + (1year/25)

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1494547200; // May 12, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1526083200; // May 12, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1494547200; // May 12, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1526083200; // May 12, 2018

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000006fce5d67766e");
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000364b0cbc3568");

        pchMessageStart[0] = 0xa9;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0x92;
        nDefaultPort = 17300;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1516676260, 1563723, 0x1e0ffff0, 1, 17500 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x5acb42f197a15d5afd611404ba94a0898cab06497f32b180256260c909b1cbfc"));
        assert(genesis.hashMerkleRoot == uint256S("0x16733a25293a66a2d0a304ee04ef55f8e7fff7d441efad46d840592d8de89028"));
     
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
//        vSeeds.push_back(CDNSSeedData("159.203.109.115", "159.203.109.115"));
//        vSeeds.push_back(CDNSSeedData("104.131.34.150", "104.131.34.150"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = true;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 7500;
        consensus.nMajorityRejectBlockOutdated = 9500;
        consensus.nMajorityWindow = 10000;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint25(0) >> 1
        consensus.nPowTargetTimespan = 120; // 2 mins
        consensus.nPowTargetSpacing = 60; // 1 min
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.nCLTVStartBlock = 1;
        consensus.nBIP66MinStartBlock = 1;
        consensus.nAuxPowStartHeight = AuxPow::START_REGTEST;
        consensus.nWitnessStartHeight = 20000;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0x2d;
        pchMessageStart[1] = 0x97;
        pchMessageStart[2] = 0x7b;
        pchMessageStart[3] = 0x37;
        nDefaultPort = 17300;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1516676260, 1563723, 0x1e0ffff0, 1, 17500 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x5acb42f197a15d5afd611404ba94a0898cab06497f32b180256260c909b1cbfc"));
        assert(genesis.hashMerkleRoot == uint256S("0x16733a25293a66a2d0a304ee04ef55f8e7fff7d441efad46d840592d8de89028"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
