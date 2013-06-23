<!-- 

function IsNumeric(str){
	var re = /[\D]/

	if (re.test(str))
	{
		return false;
	}
	return true;
}

function ValidString(str){
	var re = /[^a-zA-Z0-9_\-]/

	if (re.test(str))
	{
		return false;
	}
	return true;
}

function checkform()
{
	var frm = document.getElementById('addvdisk');

	if (!frm.targetname.value) {
		alert("VDisk name cannot be empty");
		return false;
	}

	if (frm.targetname.value.length > 36) {
		alert("VDisk name can be upto a maximum of 36 characters\n");
		return false;
	}

	if (!ValidString(frm.targetname.value))
	{
		alert("VDisk name can only contains alphabets or numbers");
		return false;
	}

	if (!frm.targetsize.value)
	{
		alert("VDisk size cannot be empty");
		return false;
	}
	if (!IsNumeric(frm.targetsize.value))
	{
		alert("VDisk size is a numeric value in Gigabytes");
		return false;
	}
	return true;
}

// -->
