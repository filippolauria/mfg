// The following code is based off a toggle menu by @Bradcomp
// source: https://gist.github.com/Bradcomp/a9ef2ef322a8e8017443b626208999c1
(function() {
    var burger = document.querySelector('.burger');
    var menu = document.querySelector('#'+burger.dataset.target);
    burger.addEventListener('click', function() {
        burger.classList.toggle('is-active');
        menu.classList.toggle('is-active');
    });
})();

function set_and_submit(uid) {
    var form_obj = document.getElementById("delete-form");
    var uid_obj = document.getElementById("uid");
    uid_obj.value = uid;
    var should_delete = confirm("Are you sure you want to delete it?");
    if (should_delete) {
        form_obj.submit();
    }
}
