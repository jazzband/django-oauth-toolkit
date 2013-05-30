#!/bin/bash
cmd="test"
for var;
do
	if [ "$var" = "-c" ]
	then
		cmd="test_coverage"
	fi
done
python manage.py $cmd oauth2_provider
