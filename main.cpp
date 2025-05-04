#include <iostream>
#include <vector>
#include <fstream>
#include <unordered_set>
#include "seal/seal.h"
#include "cryptopp/dll.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/rng.h"
#include "cryptopp/ida.h"


using namespace std;
using namespace seal;
using namespace CryptoPP;

unordered_set<string> authorized_voters = {"voter1", "voter2", "voter3", "voter4", "voter5"};

bool authenticateVoter(const string& voter_id) {
    return authorized_voters.find(voter_id) != authorized_voters.end();
}

bool zeroKnowledgeProof(const vector<int>& vote) {                              
    // Simulate a ZKP: vote must contain exactly one '1' and rest '0'
    int count = 0;
    for (int bit : vote) count += (bit == 1);
    return count == 1;
}

void SecretShareFile(int threshold, int nShares, const char *filename, const char *seed)
{
    CRYPTOPP_ASSERT(nShares >= 1 && nShares <= 1000);
    if (nShares < 1 || nShares > 1000)
        throw InvalidArgument("SecretShareFile: " + IntToString(nShares) + " is not in range [1, 1000]");

    RandomPool rng;
    rng.IncorporateEntropy((CryptoPP::byte *)seed, strlen(seed));

    ChannelSwitch *channelSwitch = NULL;
    FileSource source(filename, false, new SecretSharing(rng, threshold, nShares, channelSwitch = new ChannelSwitch));

    vector_member_ptrs<FileSink> fileSinks(nShares);
    string channel;
    for (int i = 0; i < nShares; i++)
    {
        char extension[5] = ".000";
        extension[1] = '0' + CryptoPP::byte(i / 100);
        extension[2] = '0' + CryptoPP::byte((i / 10) % 10);
        extension[3] = '0' + CryptoPP::byte(i % 10);
        fileSinks[i].reset(new FileSink((string(filename) + extension).c_str()));

        channel = WordToString<word32>(i);
        fileSinks[i]->Put((const CryptoPP::byte *)channel.data(), 4);
        channelSwitch->AddRoute(channel, *fileSinks[i], DEFAULT_CHANNEL);
    }

    source.PumpAll();
}

void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
    CRYPTOPP_ASSERT(threshold >= 1 && threshold <= 1000);
    if (threshold < 1 || threshold > 1000)
        throw InvalidArgument("SecretRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

    SecretRecovery recovery(threshold, new FileSink(outFilename));

    vector_member_ptrs<FileSource> fileSources(threshold);
    SecByteBlock channel(4);
    int i;
    for (i = 0; i < threshold; i++)
    {
        fileSources[i].reset(new FileSource(inFilenames[i], false));
        fileSources[i]->Pump(4);
        fileSources[i]->Get(channel, 4);
        fileSources[i]->Attach(new ChannelSwitch(recovery, string((char *)channel.begin(), 4)));
    }

    while (fileSources[0]->Pump(256))
        for (i = 1; i < threshold; i++)
            fileSources[i]->Pump(256);

    for (i = 0; i < threshold; i++)
        fileSources[i]->PumpAll();
}
void multiVoting(size_t poly_modulus_degree) 
{
     // SEAL setup (BFV scheme)
     EncryptionParameters params(scheme_type::bfv);
     //size_t poly_modulus_degree = 16384; //2048, 4096, 8192, 16384
     params.set_poly_modulus_degree(poly_modulus_degree);
     params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
     params.set_plain_modulus(1024);
 
     SEALContext context(params);
 
     cout << "SEALContext created with poly_modulus_degree = " << poly_modulus_degree << endl;
     auto start = chrono::high_resolution_clock::now();
 
     KeyGenerator keygen(context);
     SecretKey secret_key = keygen.secret_key();
     seal::PublicKey public_key;
     keygen.create_public_key(public_key);
 
     // Save and split SecretKey
     ofstream key_file("secret.key", ios::binary);
     secret_key.save(key_file);
     key_file.close();
 
     SecretShareFile(3, 5, "secret.key", "strongentropyseed");
 
     Encryptor encryptor(context, public_key);
     Evaluator evaluator(context);
     Decryptor decryptor(context, secret_key);
 
    // Simulate encrypted voting
     vector<pair<string, vector<int>>> authenticated_votes = {
        {"voter1", {1, 0, 0}},
        {"voter2", {0, 1, 0}},
        {"voter3", {0, 1, 0}},
        {"voter4", {0, 0, 1}},
        {"voter5", {1, 0, 0}},
        {"intruder", {1, 1, 0}} // Invalid
    };

    size_t num_candidates = 3;
    vector<Ciphertext> candidate_totals(num_candidates);
    Plaintext zero("0");
    for (size_t i = 0; i < num_candidates; i++) encryptor.encrypt(zero, candidate_totals[i]);

    for (const auto& entry : authenticated_votes) {
        const string& voter_id = entry.first;
        const vector<int>& vote = entry.second;

        if (!authenticateVoter(voter_id)) {
            cout << "Authentication failed for " << voter_id << endl;
            continue;
        }

        if (!zeroKnowledgeProof(vote)) {
            cout << "ZKP failed for " << voter_id << endl;
            continue;
        }

        for (size_t i = 0; i < num_candidates; i++) {
            Plaintext plain_vote(to_string(vote[i]));
            Ciphertext encrypted_vote;
            encryptor.encrypt(plain_vote, encrypted_vote);
            evaluator.add_inplace(candidate_totals[i], encrypted_vote);
        }
    }

    /*for (size_t i = 0; i < num_candidates; i++) {
        Plaintext plain_total;
        decryptor.decrypt(candidate_totals[i], plain_total);
        int result = stoi(plain_total.to_string());
        cout << "Total votes for Candidate " << i << ": " << result << endl;
    }*/

    char *parts[] = {
        (char *)"secret.key.000",
        (char *)"secret.key.001",
        (char *)"secret.key.002"};
    SecretRecoverFile(3, "recovered_secret.key", parts);

    ifstream rec_file("recovered_secret.key", ios::binary);
    SecretKey recovered_key;
    recovered_key.load(context, rec_file);
    rec_file.close();
    Decryptor recovered_decryptor(context, recovered_key);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = end - start;

    for (size_t i = 0; i < num_candidates; i++) {
        Plaintext plain_total;
        recovered_decryptor.decrypt(candidate_totals[i], plain_total);
        int result = stoi(plain_total.to_string());
        cout << "Recovered Decryption - Candidate " << i << ": " << result << endl;
    }
 
     cout << "\nExecution time: " << elapsed.count() << " seconds" << endl;
}

int main()
{    
    vector<int> poly_modulus_vector = {2048, 4096, 8192, 16384};

    for (size_t i = 0; i < poly_modulus_vector.size(); i++)
    {
        cout << "Testing with poly_modulus_degree = " << poly_modulus_vector[i] << endl;
        multiVoting(poly_modulus_vector[i]);
    }
    
    return 0;
}




// https://sourceforge.net/p/cryptopp/code/HEAD/tree/trunk/c5/test.cpp#l658
// https://stackoverflow.com/questions/20917558/how-to-use-shamir-secret-sharing-class-in-crypto

//evoting-test % g++ -std=c++17  main.cpp -o evoting -I/usr/local/include/SEAL-4.1  -I./sss -L/usr/local/lib -lseal-4.1 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/lib -lcryptopp