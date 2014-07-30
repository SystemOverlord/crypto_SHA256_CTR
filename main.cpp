
// Testprogramm for the crypt_sha256_ctr class


#include "crypt_sha256_ctr.h"
#include <QCoreApplication>
#include <QDebug>
#include <QFile>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    QFile testfile("/tmp/testfile");
    QString teststr;

    // Read from File works till a size of ~150kb
    if(testfile.open(QIODevice::ReadOnly))
    {
        QTextStream in(&testfile);
        while(!in.atEnd())
        {
            QString line = in.readLine();
            teststr += line;
            teststr += "\n";
        }
        testfile.close();
    }
    else teststr = QString::fromUtf8("A small Test: ßµ€öüä");


    // crypto handler
    crypt_sha256_ctr crypt;
    QString pass="Supergeheim und so!",salt="gshwlksjhfkhkjhkaskhkjhgkugejiwwpp", chipher, cleartxt;

    //encrypt teststr
    chipher=crypt.cryptQStr(teststr,pass,salt);

    qDebug()<<"QString:";
    qDebug()<< "teststr: "<< teststr;
    qDebug()<< "chipher: "<< chipher;

    //decrypt chipher
    cleartxt= crypt.cryptQStr(chipher,pass,salt);

    qDebug()<< "decrypted: "<< cleartxt;

    return a.exec();
}
