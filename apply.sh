#!/usr/bin/env bash
##
# Apply platform protection for SA-CORE-2018-002.
#
# Adds a configmap to each Openshift project which contains a nginx deployment with a PHP container.
# The configmap contains a simple PHP script to sanitize POST requests which contain keys beginning with a hash.
# The PHP container is also given an environment variable `PHP_AUTO_PREPEND_FILE` set to the path
# of the configmap, which can be used to enable/disable this behaviour.
#
# * Requires:
# - prepend.php - the source of the configmap
# - oc client tool
# - valid login to an Openshift cluster.

UNPROTECTED_PROJECTS=()

# Loop through all oc projects.
while read -r line ; do

    echo "################################################"
    echo "Checking project: $line..."
    echo "################################################"

    # Check for php container
    if oc get -n $line dc nginx | grep -q php; then

        # Check if prepend-php exists.
        if ! oc get -n $line configmaps | grep -q prepend-php; then

            # Add prepend-php config map.
            oc create -n $line configmap prepend-php --from-file=./prepend.php

            # Mount config map to php container.
            oc volume -n $line --containers="php" dc/nginx --overwrite --add -t configmap -m /usr/local/etc/php/map --name=prepend-php --configmap-name=prepend-php

            # Add PHP_AUTO_PREPEND_FILE to php container.
            oc set env -n $line --containers="php" dc/nginx PHP_AUTO_PREPEND_FILE=/usr/local/etc/php/map/prepend.php

        fi

        # Check if php container has auto_prepend_file configured.
        if oc rsh -n $line --container="php" dc/nginx grep -q /usr/local/etc/php/map/prepend.php /usr/local/etc/php/php.ini < /dev/null; then
            echo "$line is protected."
        else
            echo "$line is unprotected."
            UNPROTECTED_PROJECTS+=($line)
        fi

    fi

    echo "################################################"
    echo ""

done < <(oc projects --short)

echo "Unprotected projects:"
printf '%s\n' "${UNPROTECTED_PROJECTS[@]}"
