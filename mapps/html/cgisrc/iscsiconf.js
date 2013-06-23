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
		return false;

	return true;
}

function ValidIQNString(str){
	var re = /[^a-zA-Z0-9_\-.]/

	if (re.test(str))
		return false;

	if (str[0] == '.' || str[0] == '_' || str[0] == '-') {
		alert(str[0]);
		return false;
	}

	return true;
}

function checkModifyiSCSI()
{
	var frm = document.getElementById('iscsiconf');

	if (!ValidIQNString(frm.iqn.value)) {
		alert("IQN User can only contains alphabets or numbers");
		return false;
	}

	if (!ValidString(frm.IncomingUser.value)) {
		alert("Incoming User can only contains alphabets or numbers");
		return false;
	}

	if (!ValidString(frm.IncomingPasswd.value)) {
		alert("Incoming Passwd can only contains alphabets or numbers");
		return false;
	}

	if (!ValidString(frm.OutgoingUser.value)) {
		alert("Outgoing User can only contains alphabets or numbers");
		return false;
	}

	if (!ValidString(frm.OutgoingPasswd.value)) {
		alert("Outgoing Passwd can only contains alphabets or numbers");
		return false;
	}

	return true;

}

function checkModifyVDisk()
{
	var frm = document.getElementById('modifyvdisk');

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

	if (parseInt(frm.targetsize.value) < parseInt(frm.oldtargetsize.value)) {
		var ret = confirm("VDisk size "+frm.targetsize.value+" less than current size. Do you want to reduce the size of this VDisk ?");
		if (!ret || ret == false)
			return false;
	}
	else if (parseInt(frm.targetsize.value) != parseInt(frm.oldtargetsize.value)) {
		var ret = confirm("Do you want to increase the size of this VDisk ?");
		if (!ret || ret == false)
			return false;
	}
	return true;
}

function checkform()
{
	var frm = document.getElementById('iscsiconf');
	if (frm)
		return checkModifyiSCSI(); 

	frm = document.getElementById('modifyvdisk');
	if (frm)
		return checkModifyVDisk();

	return false;
}

// -->
