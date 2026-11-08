package network.budlum.validator.devicetests

/**
 * Structured field-test log emitter for  (`budlum-mobile-log-analyzer` TSV format).
 */
object DeviceFieldHarness {
    fun formatDeviceRecord(
        id: String,
        oem: String,
        model: String,
        androidApi: Int,
        ramMib: Int,
    ): String {
        require(androidApi >= 29) { "minSdk is 29" }
        return "kind=device\tid=$id\toem=$oem\tmodel=$model\tapi=$androidApi\tram_mib=$ramMib"
    }

    fun formatSoak24hRecord(
        id: String,
        durationSecs: Long,
        onTimeoutCalled: Boolean,
        auditsAnswered: Int,
        auditsMissed: Int,
    ): String {
        return "kind=soak24h\tid=$id\tduration_secs=$durationSecs\ton_timeout=$onTimeoutCalled\taudits_ok=$auditsAnswered\taudits_missed=$auditsMissed"
    }

    fun formatBatteryRecord(
        id: String,
        drainBps: Int,
        varianceNote: String? = null,
    ): String {
        val base = "kind=battery\tid=$id\tdrain_bps=$drainBps"
        return if (varianceNote.isNullOrBlank()) base else "$base\tnote=${varianceNote.trim()}"
    }

    fun formatNatProbeRecord(
        id: String,
        env: String,
        path: String,
    ): String {
        require(env in setOf("home_nat", "carrier_cgnat", "ipv6_only")) { "invalid NAT env $env" }
        require(path in setOf("direct", "hole_punch", "relay", "failed")) { "invalid NAT path $path" }
        return "kind=nat\tid=$id\tenv=$env\tpath=$path"
    }
}
