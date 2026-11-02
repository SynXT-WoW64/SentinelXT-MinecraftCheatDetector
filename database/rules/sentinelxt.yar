rule SentinelXT_Minecraft_Client_Namespace_Reference : sentinelxt heuristic {
    meta:
        category = "namespace_reference"
        description = "Namespace strings can also be referenced by compatibility mods; review the owning archive"
    strings:
        $meteor_ns = "meteordevelopment/meteorclient/" ascii wide nocase
        $wurst_ns = "net/wurstclient/" ascii wide nocase
        $liquid_ns = "net/ccbluex/liquidbounce/" ascii wide nocase
        $bleach_ns = "bleachhack/" ascii wide nocase
    condition:
        any of them
}

rule SentinelXT_Multiple_Cheat_Behavior_Families : sentinelxt heuristic {
    meta:
        category = "multi_family_behavior_markers"
        description = "Several distinct behavior families; investigate context and bytecode"
    strings:
        $combat1 = "killaura" ascii wide nocase
        $combat2 = "aimassist" ascii wide nocase
        $combat3 = "triggerbot" ascii wide nocase
        $movement1 = "scaffold" ascii wide nocase
        $movement2 = "flyhack" ascii wide nocase
        $movement3 = "longjump" ascii wide nocase
        $render1 = "entityesp" ascii wide nocase
        $render2 = "blockesp" ascii wide nocase
        $network1 = "packetfly" ascii wide nocase
        $network2 = "disabler" ascii wide nocase
        $player1 = "cheststealer" ascii wide nocase
        $player2 = "autototem" ascii wide nocase
    condition:
        2 of ($combat*) and
        1 of ($movement*) and
        (1 of ($render*) or 1 of ($network*) or 1 of ($player*))
}
