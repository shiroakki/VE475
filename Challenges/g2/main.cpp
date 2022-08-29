//
// Created by Adriana on 2022/7/3.
//
#include "aes.h"
#include <vector>
#include<string>
#include<iostream>
#include <fstream>
#include <cstring>
#include <sstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <getopt.h>
using std::vector;
using sstream = std::stringstream;
using namespace std;
static const string allchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.;?!()";
static const string default_key =  "??Da!CXfdi;j,o,;";
static const string CHALLENGE_CIPHERTEXT="b86f311e36601eabfa071f08ceb49d261283a62408fd4a403d047ee457f97dc6eb5e3b9f0ba7fc8e601dfe74cf12504a77431562b8948759b12fc867c7c93c8d7c0fcc0513c3be4bb2d788c3b3650af2333587875ecbd66ebd4a8feadcdea235b909dd43f661fc2141af374a9545bd1625981d58b5566eedc7208b8ac81e77bb";
/*==============================================AES implementation======================================================*/

uint8_t *deep_copy(const uint8_t key[16]){
    uint8_t *copied = (uint8_t*)malloc(16*sizeof(uint8_t));
    for(int i=0;i<16;i++){
        copied[i]=key[i];
    }
    return copied;
}
void free_key(uint8_t **key) {
    for(int i = 0; i < 11; i++) {
        free(key[i]);
    }
    free(key);
}

/*=================================================Encryption=======================================================*/
void SubBytes(uint8_t data[16]){
    for(int i=0;i<16; ++i){
        data[i]=sbox[data[i]];
    } /*data in bytes*/
}
//
void ShiftRows(uint8_t data[16]){
    //second row shift = shift left by 1 matrix[row][col]
    uint8_t temp = data[1];
    data[1] = data[5];
    data[5] = data[9];
    data[9] = data[13];
    data[13] = temp;

    //third row shift = shift left by 2
    temp = data[2];
    data[2] = data[10];
    data[10] = temp;
    temp = data[6];
    data[6] = data[14];
    data[14] = temp;

    //fourth row shift = shift right by 1
    temp = data[15];
    data[15] = data[11];
    data[11] = data[7];
    data[7] = data[3];
    data[3] = temp;
}

void MixColumns(unsigned char * state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
    tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
    tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

    tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
    tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
    tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

    tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
    tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
    tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

    tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

uint8_t **KeyExpansion(const uint8_t key[16]) {
    uint8_t **round_key = (uint8_t**)malloc(11 * sizeof(uint8_t *));
    round_key[0] = deep_copy(key);

    for(int i = 1; i < 11; i++) {
        round_key[i] = (uint8_t*)malloc(16 * sizeof(uint8_t));
    }

    for(int i = 1; i < 11; i++) {
        round_key[i][0] = round_key[i - 1][0] ^ sbox[round_key[i - 1][13]] ^ rcon[i];
        round_key[i][1] = round_key[i - 1][1] ^ sbox[round_key[i - 1][14]] ^ 0x00;
        round_key[i][2] = round_key[i - 1][2] ^ sbox[round_key[i - 1][15]] ^ 0x00;
        round_key[i][3] = round_key[i - 1][3] ^ sbox[round_key[i - 1][12]] ^ 0x00;
        for(int j = 4; j < 16; j++) {
            round_key[i][j] = round_key[i - 1][j] ^ round_key[i][j - 4];
        }
    }
    return round_key;
}


void AddRoundKey(uint8_t data[16], uint8_t *RoundKey){ //debug
    for(int i=0; i<16;++i){
        data[i] ^=RoundKey[i];
    }
}
void Rounds(uint8_t* state, uint8_t* RoundKey){
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state,RoundKey);
}
void FinalRound(uint8_t* state, uint8_t* RoundKey){
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state,RoundKey);
}


uint8_t *Encrypt(uint8_t plaintext[16], uint8_t Key[16]){

    uint8_t **expandedKeys= KeyExpansion(Key);

    uint8_t *state= deep_copy(plaintext);
    AddRoundKey(state,expandedKeys[0]);
    for(int i=1;i<10;++i) Rounds(state,expandedKeys[i]);
    FinalRound(state,expandedKeys[10]);
    free_key(expandedKeys);
//    for(int i=0;i<16;++i) encrypted_message[i]=state[i];
    return state;
}
/*=================================================Decryption=======================================================*/
void InvSubBytes(uint8_t data[16]){
    for(int i=0;i<16;++i){
        data[i] = inv_SBox[data[i]];
    }
}
void InvShiftRows(uint8_t data[16]){
    uint8_t temp = data[13];
    data[13] = data[9];
    data[9] = data[5];
    data[5] = data[1];
    data[1] = temp;

    temp = data[2];
    data[2] = data[10];
    data[10] = temp;
    temp = data[6];
    data[6] = data[14];
    data[14] = temp;

    //fourth row reverse shift =shift left by 1
    temp = data[3];
    data[3] = data[7];
    data[7] = data[11];
    data[11] = data[15];
    data[15] = temp;
}
void InverseMixColumns(unsigned char * state) {
    unsigned char tmp[16];
    tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
    tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
    tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
    tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

    tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
    tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
    tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
    tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

    tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

    tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}
void InvRounds(uint8_t*state, uint8_t*RoundKey){
    AddRoundKey(state,RoundKey);
    InverseMixColumns(state);
    InvShiftRows(state);
    InvSubBytes(state);
}
void InvFirstRound(uint8_t* state, uint8_t* RoundKey){
    AddRoundKey(state,RoundKey);
    InvShiftRows(state);
    InvSubBytes(state);
}


uint8_t *Decrypt(uint8_t ciphertext[16],uint8_t Key[16]){
//    unsigned char expandedKeys[176];
    uint8_t ** expandedKeys = KeyExpansion(Key);

    uint8_t *state= deep_copy(ciphertext);
    InvFirstRound(state,expandedKeys[10]);
    for(int i=8; i>=0;--i) InvRounds(state,expandedKeys[i+1]);

    AddRoundKey(state,expandedKeys[0]);
    free_key(expandedKeys);
//    for(int i=0;i<16;++i) decrypted_message[i]=state[i];
    return state;
}

/*==============================================I/O specifics======================================================*/

vector<uint8_t> word_to_byte(string word){
    vector<uint8_t>chars;
    for(int i=0; i < word.length(); ++i){
        chars.push_back((int) word[i]);
    }
    return chars;
}
uint8_t transform(uint8_t phrase){
    uint8_t res ={};
    if(phrase=='a' || phrase=='b' || phrase=='c' || phrase=='d'||phrase=='e' || phrase=='f')
        res=phrase-'a'+10;
    else
        res=phrase-'0';

    return res;
}

string byte_to_plain(uint8_t *chars, int length){
    string res;
    for(int i=0;i<length;++i){
        if(chars[i]==0) {
            break;
        }
        else{
            auto idx = allchars.find((char)chars[i]);
            if(idx!=string::npos){
                res+=(char)chars[i];
            }
            else {
//                cout<<"Invalid Ciphertext!"<<endl;
//                return "";
                res+= allchars[(int)chars[i]%69];}
        }
    }
    return res;
}

void print_message(uint8_t *message, int length){
//    uint8_t len = 16;
    for(int i =0;i<length;++i) {
        printf("%02x", message[i]);
    }
    printf("\n");
}
/*==============================================KeyGeneration/Encryption/Decryption======================================================*/
string generate(bool use_default=false){
    if(use_default) return default_key;
    string key;
//    srand(time(NULL));
//    for(int i=0;i<16;++i) key+=allchars[rand()%69];
//return key;
    std::random_device rd;
    std::mt19937 gen(rd());
    for(int i=0;i<16;++i) key+=allchars[gen()%69];
    return key;
}

string generate_IV(){
    std::random_device rd;
    std::mt19937 gen(rd());
    string IV="";
    for (int i=0;i<16;++i) IV[i]=gen()%128;
    return IV;
}

uint8_t *AES_encrypt(const string&message, const string & Key, int &length, string IV){
    vector<uint8_t> plaintext = word_to_byte(message);
    vector<uint8_t> byte_keys = word_to_byte(Key);
    string IV_new = IV;
    /*message padding*/
    int original_len = plaintext.size();
    int padded_len = original_len;
    if((padded_len%16)!=0) {
        padded_len = (padded_len/16+1)*16;
    }

    vector<uint8_t> paddedMessage;
    for(int i=0;i<padded_len;++i){
        if(i>=original_len) paddedMessage.push_back(0x00); //debug
        else paddedMessage.push_back(plaintext[i]);
    }

    uint8_t encrypt_keys[16];
    for(int i=0;i<16;++i)
        encrypt_keys[i]=byte_keys[i];

    vector<uint8_t> cipher(paddedMessage.size());
    for(int i=0;i<paddedMessage.size();i+=16){
        uint8_t temp[16]={};
        for(int j=0;j<16;++j){
            temp[j] = paddedMessage[i+j];
//            cerr<<"temp[j]: "<<(int)temp[j]<<" ";
            temp[j] = temp[j]^IV_new[j]; //not sure if it works
//            cerr<<"temp[j] after: "<<temp[j]<<endl;
        }
        uint8_t *ciphertext = Encrypt(temp,encrypt_keys);
//        print_message(ciphertext,16); //debug
        for(int j=0;j<16;j++){
            cipher[i+j]=ciphertext[j];
            IV_new[j]= ciphertext[j]^paddedMessage[i+j];
        }
        free(ciphertext);
    }


    length=paddedMessage.size();
    uint8_t *final = new uint8_t [paddedMessage.size()];
    for(int i=0;i<paddedMessage.size();++i) final[i] = cipher[i];
    return final;
}


string AES_decrypt(string& ciphertext, const string& Key, int &length,const string IV){
    if(((ciphertext.length()) % 32)!=0){
        cout<<"Invalid ciphertext"<<endl;
        return 0;
    }

    string IV_new = IV;

    vector<uint8_t> byte_keys = word_to_byte(Key);
    uint8_t encrypt_keys[16];
    for(int i=0;i<16;++i)
        encrypt_keys[i]=byte_keys[i];

    length=ciphertext.length();
//    cerr<<"length of ciphertext: "<<length<<endl;
    string final="";

    uint8_t cipher_char[16];
    for(int j=0;j<length/2;j+=16){
        for(int i=0;i<16;++i){
//            cerr<<"cipher: "<<ciphertext[2*i+j]<<" ";
            cipher_char[i] = transform(ciphertext[2*i+2*j])*16+transform(ciphertext[2*i+1+2*j]);
//            cerr<<hex<<(int)cipher_char[i]<<" ";
        }
        // print_message(cipher_char,16);
        uint8_t *plain = Decrypt(cipher_char,encrypt_keys);
//        print_message(plain,16);
        for(int i=0;i<16;++i){
//            cerr<<"plain: "<<hex<<(int)plain[i]<<endl;

            plain[i]= plain[i]^IV_new[i];
            IV_new[i] = cipher_char[i]^plain[i];

//            cerr<<"plain after IV: "<<hex<<(int)plain[i]<<endl;
//            cerr<<"IV: "<<hex<<(int)IV_new[i]<<endl;
        }
        final+=byte_to_plain(plain,16);
    }
    return final;

}


/*=====================================================================================================*/

enum Operation {
    ENCRYPT,
    DECRYPT,
    GENERATE,
    NONE
};

int main(int argc, char*argv[]){
    int opt,length=0;
    string message, keyloc ="";
    Operation operation=NONE;
    auto key=generate(true);
//    string IV = generate_IV();
    string IV = "5e7e532842091727";
    static option opts[] = { { "generate", no_argument, NULL, 'g' },
                             { "decrypt", required_argument, NULL, 'd' },
                             { "encrypt", required_argument, NULL, 'e' },
                             { "key", required_argument, NULL, 'k' },
                             { NULL, 0, NULL, 0 } };

    while ((opt = getopt_long(argc, argv, ":gd:e:k:", opts, NULL)) != -1)
        switch (opt) {
            case 'g': {
                if (operation == NONE)
                    operation = GENERATE;
                break;
            }
            case 'd': {
                if (operation == NONE)
                {
                    operation = DECRYPT;
                    message = optarg;
                }
                break;
            }
            case 'e': {
                if (operation == NONE)
                {
                    operation = ENCRYPT;
                    message = optarg;
                }
                break;
            }
            case 'k': {
                keyloc = optarg;
                break;
            }
        }
    if (keyloc != "") {
        std::fstream keyfile(keyloc);
        keyfile >> key;
        char c;
        keyfile.getline(&c, 1);
        if (keyfile.fail() || c != '\0')
            throw std::runtime_error("invalid key");
        keyfile.close();
    }

    switch (operation) {
        case GENERATE: {
            cout << generate() << endl;
            break;
        }
        case DECRYPT: {
            /*TODO*/
            if (message == CHALLENGE_CIPHERTEXT && keyloc == "")
                cout << "cheater: it is forbidden to decrypt the challenge ciphertext" << endl;
            else{
                string plain= AES_decrypt(message,key,length,IV);
                for(int i=0;i<plain.length();++i) cout<<plain[i];
                cout<<endl;
            }
            break;
        }
        case ENCRYPT: {
            /*TODO*/
//            cout << AES_encrypt(message, key) << endl;
//            AES_encrypt(message,key);
//            int length=0;
//debug info
//            for(int i=0;i<16;++i) cerr<<hex<<(int)IV[i]<<" ";
//            cerr<<endl;
            uint8_t *cipher = AES_encrypt(message,key,length,IV);
//            int  n= sizeof(cipher);
//            cerr<<"size: "<<n<<endl;
            print_message(cipher,length);
            break;
        }
        case NONE: {
            cout << "there is nothing to do" << endl;
            break;
        }
    }
        return 0;
}