$(document).ready(function () {
  let selector = null;
  let selectedPrivateKey = {
    id: null,
    key: null,
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
    let site_url = "http://localhost:5000";

    let formdata1 = {
      enc_msg: $("#enc_msg").is(":checked"),
      sign: $("#sign").is(":checked"),
      compress: $("#compress").is(":checked"),
      radix64: $("#radix64").is(":checked"),
      text: $("#input_of_type_textarea").val(),
      file: $("#input_of_type_file")[0].files[0],
      text_or_file: $("#input_type").val(),
    };

    let formdata2 = {
      type: "POST",
      contentType: "application/json",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      data: JSON.stringify(formdata1),
      dataType: "json",
      url: site_url + "/encr_api",
      success: function (data) {
        console.log(JSON.stringify(data));
      },
    };
    $.ajax(formdata2);
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
        }
        selectedPrivateKey.id = $(this).closest("tr").find(".key-id").text();
        selectedPrivateKey.key = $(this).siblings("textarea").val();
        selectedPrivateKey.element = $(this).siblings("textarea");
        selectedPrivateKey.element.addClass("selected");
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
        // Optionally, you could refresh the keys list here
        location.reload(); // Refreshes the page to show the new key pair
      },
      error: function (error) {
        alert("Error generating key pair");
        console.log(error);
      },
    });
  });
});
