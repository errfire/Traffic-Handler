
// Funktion zum Vergleichen der Versionen
function compareVersions(currentVersion, serverVersion) {
    const current = currentVersion.split('.').map(Number);
    const server = serverVersion.split('.').map(Number);

    for (let i = 0; i < current.length; i++) {
        if (current[i] < server[i]) {
            return true; // Neue Version verfügbar
        } else if (current[i] > server[i]) {
            return false; // Aktuelle Version ist neuer
        }
    }

    return false; // Keine neue Version
}

// Hole die Versionsnummern und führe den Vergleich durch
fetch('https://traffichandler.err-fire.de/updater/manifest.json')
    .then(response => response.json())
    .then(data => {
        const serverVersion = data.version;
        const currentVersion = '{{ app.Version }}'; // Hier die Versionsnummer deiner Webseite einfügen

        if (compareVersions(currentVersion, serverVersion)) {
            // Zeige ein Pop-Up an
            alert('Neue Version vom ERR-FIRE Traffic Handler verfügbar!');
        }
    })
    .catch(error => {
        console.error('Fehler beim Laden der Versionsnummer:', error);

    });
