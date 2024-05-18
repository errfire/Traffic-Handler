/*  Updater JavaScript Code for ERR-Fire */
/* Author: Billel Meftah */

function compareVersions(currentVersion, serverVersion) {
    const current = currentVersion.split('.').map(Number);
    const server = serverVersion.split('.').map(Number);

    for (let i = 0; i < current.length; i++) {
        if (current[i] < server[i]) {
            return true;
        } else if (current[i] > server[i]) {
            return false;
        }
    }

    return false;
}


fetch('https://updater.err-fire.de/updater/manifest.json', {cache: "reload"})
    .then(response => response.json())
    .then(data => {
        const serverVersion = data.Version;
        const currentVersion = "0.6.0";

        if (compareVersions(currentVersion, serverVersion)) {

            alertContainer.innerHTML = `
                <div class="alert alert-warning alert-dismissible fade show" role="alert">
                    <strong>Eine neue Version ${serverVersion} wurde veröffentlicht!</strong> Sie verwenden eine ältere Version. <a href="https://updater.err-fire.de/TrafficHandler/beta/${serverVersion}-Beta/Docker-Compose/traffichandler-docker-${serverVersion}-Beta.tar" class="alert-link">Jetzt herunterladen</a> 
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>`;
        }

    })
    .catch(error => {
        console.error('Fehler beim Laden der Versionsnummer:', error);

    })
    var alertList = document.querySelectorAll('.alert')
    alertList.forEach(function (alert) {
      new bootstrap.Alert(alert)
    });
