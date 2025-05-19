# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .misc import info, head, get_hsm, get_sgx_hsm, dispose_hsm, AdminError
from .unlock import do_unlock
from .sgx_migration_authorization import SGXMigrationAuthorization
from sgx.hsm2dongle import SgxUpgradeRoles


def do_migrate_db(options):
    head("### -> Migrate DB", fill="#")
    hsm_src = None
    hsm_dst = None

    if options.destination_sgx_port is None or \
       options.destination_sgx_host is None:
        raise AdminError("Destination SGX powHSM host and port must be provided")

    # Require a migration authorization file
    if options.migration_authorization_file_path is None:
        raise AdminError("No migration authorization file path given")

    # Load the given migration authorization
    try:
        migration_authorization = SGXMigrationAuthorization.from_jsonfile(
            options.migration_authorization_file_path)
        # Require at least one signature
        if len(migration_authorization.signatures) == 0:
            raise RuntimeError("At least one signature is needed to "
                               "perform a DB migration")
        # Perform conversions
        source_mre = bytes.fromhex(migration_authorization.migration_spec.exporter)
        destination_mre = bytes.fromhex(migration_authorization.migration_spec.importer)
        signatures = list(map(
            lambda s: bytes.fromhex(s),
            migration_authorization.signatures))
    except Exception as e:
        raise AdminError(f"While loading the migration authorization file: {str(e)}")

    # Attempt to unlock the source device
    try:
        do_unlock(options, label=False)
    except Exception as e:
        raise AdminError(f"Failed to unlock device: {str(e)}")

    # DB migration
    info("Migrating DB... ", options.verbose)
    try:
        hsm_src = get_hsm(options.verbose)
        hsm_dst = get_sgx_hsm(
            options.destination_sgx_host,
            options.destination_sgx_port,
            options.verbose)

        info("Sending source spec...", nl=False)
        hsm_src.migrate_db_spec(
            SgxUpgradeRoles.EXPORTER, source_mre, destination_mre, signatures)
        info("OK")
        info("Sending destination spec...", nl=False)
        hsm_dst.migrate_db_spec(
            SgxUpgradeRoles.IMPORTER, source_mre, destination_mre, signatures)
        info("OK")

        info("Getting source evidence...", nl=False)
        src_evidence = hsm_src.migrate_db_get_evidence()
        info(f"OK. Got {len(src_evidence)} bytes")
        info("Getting destination evidence...", nl=False)
        dst_evidence = hsm_dst.migrate_db_get_evidence()
        info(f"OK. Got {len(dst_evidence)} bytes")

        info("Sending destination evidence to source...", nl=False)
        hsm_src.migrate_db_send_evidence(dst_evidence)
        info("OK")
        info("Sending source evidence to destination...", nl=False)
        hsm_dst.migrate_db_send_evidence(src_evidence)
        info("OK")

        info("Getting data from source...", nl=False)
        migration_data = hsm_src.migrate_db_get_data()
        info("OK")
        info("Sending data to destination...", nl=False)
        hsm_dst.migrate_db_send_data(migration_data)
        info("OK")
    except Exception as e:
        raise AdminError(f"Failed to migrate DB: {str(e)}")
    finally:
        dispose_hsm(hsm_src)
        dispose_hsm(hsm_dst)

    info("DB migrated successfully")
