$(document).ready(function(){
	$(".navbar-dropdown-startRight").each(function(i, obj) {
		var navSpace = $(obj).parent().width();
		navSpace -= $(obj).width();
		// console.log(navSpace);
		$(obj).css({ left: navSpace });
    });

	$("#user_settings_dropdown_trigger").click(function() {
		$("#user_settings_dropdown_trigger").parent().toggleClass('is-active');
	});
});
