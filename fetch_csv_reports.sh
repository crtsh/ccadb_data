#!/bin/bash

CURDIR=`pwd`
TMPDIR=`mktemp -d`
cd $TMPDIR

wget -nv -O AllCertificateRecordsCSVFormatV5 https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5
if [ -s AllCertificateRecordsCSVFormatV5 ]; then
  csvsort AllCertificateRecordsCSVFormatV5 > AllCertificateRecordsCSVFormatV5.sorted
  mv AllCertificateRecordsCSVFormatV5.sorted AllCertificateRecordsCSVFormatV5
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
if [ -s $TMPDIR/AllCertificateRecordsCSVFormatV5 ]; then
  mv $TMPDIR/AllCertificateRecordsCSVFormatV5 $CURDIR/data
fi
mv $TMPDIR/* $CURDIR/cmd/ski_spki/data
rmdir $TMPDIR

cd cmd/ski_spki
./gen_ski_spki_csv.sh
cd $CURDIR
