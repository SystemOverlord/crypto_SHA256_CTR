#include "crypt_sha256_ctr.h"

//
std::vector<u_int32_t> crypt_sha256_ctr::crypt(std::vector<u_int32_t> data, std::vector<u_int32_t> key, std::vector<u_int32_t> nounce)
{
    // data have to contain the cleartext data for encryption and the chiphered data for decryption
    // key have to contain the encryption-key
    // nounce have to contain random data you can safe in cleartext (also called salt)

    std::vector<u_int32_t> erg; // for return data
    std::string inp;            // the input of the sha256 class requires std::string as input

    // add key and nounce to input string
    inp += VecUINT32ToStdStr(key);
    inp += VecUINT32ToStdStr(nounce);

    // loop to iterate throu the data
    for(std::vector<u_int32_t>::size_type i=0; i<data.size(); i=i+8)
    {
        // add count to sha input for round key
        std::string inp_r = inp;
        inp_r = inp + ToStdStr(i);
        // calc the sha256 hash of key + nounce + count
        crypto::sha256 sha;
        std::vector<u_int32_t> sha_erg = sha(inp_r);

        // XOR the sha256 result and a 256bit data block
        for(std::vector<u_int32_t>::size_type j=0;j<8 && (i+j)<data.size();j++)
            erg.push_back(data[i+j] ^ sha_erg[j]);
    }
    return erg;
}

QString crypt_sha256_ctr::cryptQStr(QString data, QString key, QString nounce)
{
    std::vector<u_int32_t> v_data, v_key, v_nounce;
    v_data      = QStrToVecUInt32(data);
    v_key       = QStrToVecUInt32(key);
    v_nounce    = QStrToVecUInt32(nounce);
    return VecUInt32ToQStr(crypt(v_data,v_key,v_nounce));
}

std::string crypt_sha256_ctr::VecUINT32ToStdStr(std::vector<u_int32_t> data)
{
    std::string erg;
    for(std::vector<u_int32_t>::size_type i=0;i<data.size();i++)
    {
        char a=0,b=0,c=0,d=0;
        u_int32_t tmp=data[i];
        a = a|tmp;
        tmp = tmp>>8;
        b = b|tmp;
        tmp = tmp>>8;
        c = c|tmp;
        tmp = tmp>>8;
        d = d|tmp;
        erg.push_back(d);
        if(c!=0) erg.push_back(c);
        if(b!=0) erg.push_back(b);
        if(a!=0) erg.push_back(a);
    }
    return erg;
}

std::vector<u_int32_t> crypt_sha256_ctr::QStrToVecUInt32(QString str)
{
    std::vector<ushort> erg16;
    std::vector<u_int32_t> erg;

    for(int i=0; i<str.length();i++)
        erg16.push_back(str[i].unicode());

    for(std::vector<u_int32_t>::size_type i=0; i< erg16.size();i=i+2)
    {
        u_int32_t tmp=0;
        tmp = tmp|erg16[i];
        tmp = tmp << 16;
        if((i+1)<erg16.size()) tmp = tmp|erg16[i+1];
        erg.push_back(tmp);
    }

    return erg;
}

QString crypt_sha256_ctr::VecUInt32ToQStr(std::vector<u_int32_t> vec)
{
    std::vector<ushort> erg16;
    QString erg;
    for(std::vector<u_int32_t>::size_type i=0; i<vec.size(); i++)
    {
        u_int32_t tmp= vec[i];
        ushort a=0,b=0;
        a = a|tmp;
        tmp = tmp >> 16;
        b = b|tmp;
        erg16.push_back(b);
        if(a!=0) erg16.push_back(a);

    }

    for(std::vector<u_int32_t>::size_type i=0; i<erg16.size(); i++)
        erg.push_back(QChar(erg16[i]));

    return erg;
}
