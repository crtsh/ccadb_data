#!/bin/bash

CURDIR=`pwd`
TMPDIR=`mktemp -d`
cd $TMPDIR

wget -nv https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2

for i in $( seq 1994 `date +%Y` ); do
  wget -nv -O AllCertificatePEMsCSVFormat_NotBeforeYear_$i https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear=$i
done

cd $CURDIR
mkdir -p data
mv $TMPDIR/AllCertificateRecordsCSVFormatv2 $CURDIR/data
mv $TMPDIR/* $CURDIR/cmd/ski_spki/data
rmdir $TMPDIR
