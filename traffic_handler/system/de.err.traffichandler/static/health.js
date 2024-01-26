document.addEventListener("DOMContentLoaded", function() {
    const trigger = document.getElementById("cloud-icon");
    const popup = document.getElementById("popup-text");

   
    trigger.addEventListener("mouseover", function() {

        popup.style.display = "block";
    });

    trigger.addEventListener("mouseout", function() {
        popup.style.display = "none";
    });
});

function checkServerStatus() {
    const address = "https://updater.err-fire.de"
    axios.get(address)
        .then(function (response) {
            if (response.status === 200) {

                document.getElementById('cloud-icon').src = "static/greencloud.png";
                document.getElementById('popup-text').textContent = "Verbindung zum Updateserver.";
            } else {
                document.getElementById('cloud-icon').src = "static/greycloud.png";
                document.getElementById('popup-text').textContent = "Keine Verbindung zum Updateserver.";
            }
        })
        .catch(function (error) {
            document.getElementById('cloud-icon').src = "static/greycloud.png";
            document.getElementById('popup-text').textContent = "Keine Verbindung zum Updateserver.";
        });
}


setInterval(checkServerStatus, 60000);
checkServerStatus();

