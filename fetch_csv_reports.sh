#!/bin/bash

CURDIR=`pwd`
TMPDIR=`mktemp -d`
cd $TMPDIR

wget -nv -O AllCertificateRecordsCSVFormatv4 https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4a
if [ -s AllCertificateRecordsCSVFormatv4 ]; then
  wget -nv https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4b
  if [ -s AllCertificateRecordsCSVFormatV4b ]; then
    sed -i -e '$a\' AllCertificateRecordsCSVFormatv4
    tail -n +1 AllCertificateRecordsCSVFormatV4b >> AllCertificateRecordsCSVFormatv4
    csvsort AllCertificateRecordsCSVFormatv4 > AllCertificateRecordsCSVFormatv4.sorted
    mv AllCertificateRecordsCSVFormatv4.sorted AllCertificateRecordsCSVFormatv4
  fi
  rm -f AllCertificateRecordsCSVFormatV4b
fi

for i in $( seq 1994 `date +%Y` ); do
  wget -nv -O AllCertificatePEMsCSVFormat_NotBeforeYear_$i https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear=$i
  if [ -s AllCertificatePEMsCSVFormat_NotBeforeYear_$i ]; then
    csvsort AllCertificatePEMsCSVFormat_NotBeforeYear_$i > AllCertificatePEMsCSVFormat_NotBeforeYear_$i.sorted
    mv AllCertificatePEMsCSVFormat_NotBeforeYear_$i.sorted AllCertificatePEMsCSVFormat_NotBeforeYear_$i
  else
    rm -f AllCertificatePEMsCSVFormat_NotBeforeYear_$i
  fi
done

cd $CURDIR
mkdir -p data
if [ -s $TMPDIR/AllCertificateRecordsCSVFormatv4 ]; then
  mv $TMPDIR/AllCertificateRecordsCSVFormatv4 $CURDIR/data
fi
mv $TMPDIR/* $CURDIR/cmd/ski_spki/data
rmdir $TMPDIR

cd cmd/ski_spki
./gen_ski_spki_csv.sh
cd $CURDIR
