$(document).ready(function () {
  let selector = null;
  let selectedPrivateKey = {
    id: null,
    key: null,
    password: null,
  };
  let selectedPublicKey = {
    id: null,
    key: null,
  };

  $("#alt_input1").addClass("collapse");
  $("#alt_input2").addClass("collapse");
  $("#input_type").change(function () {
    selector = ".input_" + $(this).val();
    $("#alt_input1").collapse("hide");
    $("#alt_input2").collapse("hide");
    if (selector === ".input_text") $("#alt_input1").collapse("show");
    else $("#alt_input2").collapse("show");
  });
  $("#alt_input1").collapse("show");

  $("#encr_message").click(function () {
    let form_data = new FormData();

    form_data.append("aes_enc_msg", $("#aes_enc_msg").is(":checked"));
    form_data.append("des3_enc_msg", $("#3des_enc_msg").is(":checked"));
    form_data.append("private_key_id", selectedPrivateKey.id);
    form_data.append("private_key_password", selectedPrivateKey.password);
    form_data.append("public_key_id", selectedPublicKey.id);
    form_data.append("sign", $("#sign").is(":checked"));
    form_data.append("compress", $("#compress").is(":checked"));
    form_data.append("radix64", $("#radix64").is(":checked"));
    form_data.append("text", $("#input_of_type_textarea").val());
    form_data.append("file", $("#input_of_type_file").prop("files")[0]);
    form_data.append("text_or_file", $("#input_type").val());
    form_data.append("op_type", $("#operation_type").val());

    $.ajax({
      url: "/encr_api",
      type: "POST",
      data: form_data,
      processData: false,
      contentType: false,
      success: function (data, textStatus, jqXHR) {
        console.log(JSON.stringify(data));
        $("#input_of_type_textarea").val(data);
      },
      error: function (jqXHR, textStatus, errorThrown) {
        //if fails
      },
    });
  });

  // Fetch and display private keys
  $.ajax({
    url: "/list_private_key_ring",
    type: "GET",
    success: function (data) {
      let keysTable = $("#private-keys-table tbody");
      keysTable.empty();

      data.private_key_ring.forEach((key) => {
        keysTable.append(`
                    <tr>
                        <td>${key.timestamp}</td>
                        <td>${key.name}</td>
                        <td class="key-id">${key.key_id}</td>
                        <td>
                            <textarea readonly>${key.public_key}</textarea>
                            <button class="btn btn-sm btn-primary select-my-public-key">Select</button>
                        </td>
                        <td>
                            <textarea readonly>${key.private_key}</textarea>
                            <button class="btn btn-sm btn-primary select-private-key">Select</button>
                        </td>
                        <td>${key.user_id}</td>
                        <td>
                            <button class="btn btn-sm btn-danger remove-key">Remove</button>
                        </td>
                    </tr>
                `);
      });

      $(".select-private-key").click(function () {
        if (selectedPrivateKey.id) {
          $(selectedPrivateKey.element).removeClass("selected");
          selectedPrivateKey.id = null;
          selectedPrivateKey.password = null;
        }
        selectedPrivateKey.id = $(this).closest("tr").find(".key-id").text();
        selectedPrivateKey.key = $(this).siblings("textarea").val();
        selectedPrivateKey.element = $(this).siblings("textarea");
        $("#passwordModal").modal("show");
      });

      $("#passwordForm").submit(function (event) {
        event.preventDefault();
        selectedPrivateKey.password = $("#privateKeyPassword").val();

        // Call API to get private key
        $.ajax({
          url: `/get_private_key_by_id/${selectedPrivateKey.id}`,
          type: "POST",
          contentType: "application/json",
          data: JSON.stringify({ password: selectedPrivateKey.password }),
          success: function (response) {
            // If the response is 200, select the element
            if (!response.key_id) {
              console.log(response);
            } else {
              // Response is successful, select the element
              selectedPrivateKey.element.addClass("selected");
              $("#passwordModal").modal("hide");
            }
          },
          error: function (error) {
            alert("Error fetching private key");
            console.log(error);
          },
        });
      });

      $(".select-my-public-key").click(function () {
        if (selectedPublicKey.id) {
          $(selectedPublicKey.element).removeClass("selected");
        }
        selectedPublicKey.id = $(this).closest("tr").find(".key-id").text();
        selectedPublicKey.key = $(this).siblings("textarea").val();
        selectedPublicKey.element = $(this).siblings("textarea");
        selectedPublicKey.element.addClass("selected");
      });

      $(".remove-key").click(function () {
        const keyId = $(this).closest("tr").find(".key-id").text();
        if (
          confirm(`Are you sure you want to remove the key with ID: ${keyId}?`)
        ) {
          $.ajax({
            url: "/remove_key",
            type: "DELETE",
            contentType: "application/json",
            data: JSON.stringify({ key_id: keyId }),
            success: function (response) {
              alert(response.message);
              location.reload(); // Refreshes the page to show the updated key ring
            },
            error: function (error) {
              alert("Error removing key pair");
              console.log(error);
            },
          });
        }
      });
    },
    error: function (error) {
      alert("Error fetching private keys");
      console.log(error);
    },
  });

  // Fetch and display public keys
  $.ajax({
    url: "/list_public_key_ring",
    type: "GET",
    success: function (data) {
      let keysTable = $("#public-keys-table tbody");
      keysTable.empty();

      data.public_key_ring.forEach((key) => {
        keysTable.append(`
                    <tr>
                        <td>${key.timestamp}</td>
                        <td>${key.name}</td>
                        <td class="key-id">${key.key_id}</td>
                        <td>
                            <textarea readonly>${key.public_key}</textarea>
                            <button class="btn btn-sm btn-primary select-public-key">Select</button>
                        </td>
                        <td>${key.user_id}</td>
                    </tr>
                `);
      });

      $(".select-public-key").click(function () {
        if (selectedPublicKey.id) {
          $(selectedPublicKey.element).removeClass("selected");
        }
        selectedPublicKey.id = $(this).closest("tr").find(".key-id").text();
        selectedPublicKey.key = $(this).siblings("textarea").val();
        selectedPublicKey.element = $(this).siblings("textarea");
        selectedPublicKey.element.addClass("selected");
      });
    },
    error: function (error) {
      alert("Error fetching public keys");
      console.log(error);
    },
  });

  // Handle form submission for generating new key pair
  $("#generateKeyForm").submit(function (event) {
    event.preventDefault();
    const formData = {
      name: $("#keyName").val(),
      email: $("#keyEmail").val(),
      password: $("#keyPassword").val(),
      key_size: $("#keySize").val(),
    };

    $.ajax({
      url: "/generate_key_pair",
      type: "POST",
      contentType: "application/json",
      data: JSON.stringify(formData),
      success: function (response) {
        alert(response.message);
        $("#generateKeyModal").modal("hide");
        location.reload(); // Refreshes the page to show the new key pair
      },
      error: function (error) {
        alert("Error generating key pair");
        console.log(error);
      },
    });
  });

  // Handle form submission for importing public key
  $("#importPublicKeyForm").submit(function (event) {
    event.preventDefault();
    const file = $("#importFile")[0].files[0];
    const userId = $("#importUserId").val();
    const keyName = $("#importKeyName").val();

    if (!file) {
      alert("Please select a file.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("user_id", userId);
    formData.append("name", keyName);

    $.ajax({
      url: "/import_public_key",
      type: "POST",
      data: formData,
      processData: false, // Prevent jQuery from automatically transforming the data into a query string
      contentType: false, // Prevent jQuery from overriding the Content-Type header
      success: function (response) {
        alert(response.message);
        $("#importPublicKeyModal").modal("hide");
        location.reload(); // Refreshes the page to show the imported key
      },
      error: function (error) {
        alert("Error importing public key");
        console.log(error);
      },
    });
  });
});
