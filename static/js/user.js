document.addEventListener('DOMContentLoaded', function() {
	var i;
    
    var cardToggles = document.getElementsByClassName('card-toggle');
	for (i = 0; i < cardToggles.length; i++) {
		cardToggles[i].addEventListener('click', function(e){
            var card = e.currentTarget.parentElement.parentElement;
            card.getElementsByClassName('card-content')[0].classList.toggle('is-hidden');
		});
	}
    
    var form_obj = document.getElementById("delete-form");
    var uid_obj = document.getElementById("uid");
    
    var userDeleters = document.getElementsByClassName('delete-user');
    for (i = 0; i < userDeleters.length; i++) {
        userDeleters[i].addEventListener('click', function(e){
            uid_obj.value = this.getAttribute('data-uid');
            var should_delete = confirm("Are you sure you want to delete this user?");
            if (should_delete) {
                form_obj.submit();
            }
        });
    }
});
