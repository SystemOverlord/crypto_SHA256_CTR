//
// THIS SOFTWARE IS NOT TESTED AND PROVIDES INSECURE ENCRYPTION.
// DO NOT USE IT IN SERIOUS BUISNESS!
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
// FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// software written by
// Olaf Pichler, system.overlord@magheute.net
//
#ifndef CRYPT_SHA256_CTR_H
#define CRYPT_SHA256_CTR_H

#include "sha256.h"
#include "utils.h"
#include <QString>
#include <vector>

class crypt_sha256_ctr
{
    public:
        crypt_sha256_ctr(){}
        // The actuall encryption and decryption
        std::vector<u_int32_t> crypt(std::vector<u_int32_t> data, std::vector<u_int32_t> key, std::vector<u_int32_t> nounce);
        // data have to contain the cleartext data for encryption and the chiphered data for decryption
        // key have to contain the encryption-key
        // nounce have to contain random data you can safe in cleartext (also called salt)

        // Qstring and implementations of crypt
        QString cryptQStr(QString data, QString key, QString nounce);

        // Functions to convert QString to std::vector<u_int32_t>  and return
        QString VecUInt32ToQStr(std::vector<u_int32_t> vec);
        std::vector<u_int32_t> QStrToVecUInt32(QString str);

    private:
        // Functions to convert std::vector<u_int32_t> to std::string
        std::string VecUINT32ToStdStr(std::vector<u_int32_t> data);
};

#endif // CRYPT_SHA256_CTR_H
