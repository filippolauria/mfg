function setAndSubmit(uid) {
  $("uid").value = uid;
  var should_delete = confirm("Are you sure you want to delete it?");
  if (should_delete) {
    $("delete-form").submit();
  }
}

function generateDeleteButtons(virtualFormSelector, virtualUidSelector, dataAttributeName, deleteButtonsSelector) {
  $(deleteButtonsSelector).each(function(i, elem) {
    $(virtualUidSelector).val($(elem).data(dataAttributeName));

    $(elem).click(function(){
      var should_delete = confirm("Are you sure you want to delete it?");
      if (should_delete) {
        $(virtualFormSelector).submit();
      }
    });
    
  });
}

function generatePasswordTogglerAndShuffler(
  password1Selector, password2Selector, buttonShowHideSelector, buttonRandomSelector, randomPasswordURL) {

  var passwordElements = [ password1Selector, password2Selector ];
    
  $(buttonShowHideSelector).click(function(){
    $(this).find("i").toggleClass("bi-eye-fill").toggleClass("bi-eye-slash-fill");
    $.each(passwordElements, function(i, elem){
      $(elem).attr("type", function(index, attr){
        return attr == "password" ? "text" : "password";
      });
    });
  });

  $(buttonRandomSelector).click(function(){
    $.ajax({
      url: randomPasswordURL,
      success: function(word){
        $.each(passwordElements, function(i, elem){
          $(elem).val(word);
        });
      }
    });
  });
  
  $(password1Selector).attr("tabindex", 1);
  $(password2Selector).attr("tabindex", 2);
  $(password1Selector).closest("form").find(":submit").attr("tabindex", 3);
  $(buttonShowHideSelector).attr("tabindex", 4);
  $(buttonRandomSelector).attr("tabindex", 5);
}
