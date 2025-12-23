#!/bin/bash

CURDIR=`pwd`
TMPDIR=`mktemp -d`
cd $TMPDIR

wget -nv https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4
csvsort AllCertificateRecordsCSVFormatv4 > AllCertificateRecordsCSVFormatv4.sorted
mv AllCertificateRecordsCSVFormatv4.sorted AllCertificateRecordsCSVFormatv4

for i in $( seq 1994 `date +%Y` ); do
  wget -nv -O AllCertificatePEMsCSVFormat_NotBeforeYear_$i https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear=$i
  csvsort AllCertificatePEMsCSVFormat_NotBeforeYear_$i > AllCertificatePEMsCSVFormat_NotBeforeYear_$i.sorted
  mv AllCertificatePEMsCSVFormat_NotBeforeYear_$i.sorted AllCertificatePEMsCSVFormat_NotBeforeYear_$i
done

cd $CURDIR
mkdir -p data
mv $TMPDIR/AllCertificateRecordsCSVFormatv4 $CURDIR/data
mv $TMPDIR/* $CURDIR/cmd/ski_spki/data
rmdir $TMPDIR

cd cmd/ski_spki
./gen_ski_spki_csv.sh
cd $CURDIR
