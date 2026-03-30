let chartInstance = null;

function lookupIOC() {

    const ioc = document.getElementById("iocInput").value.trim();

    if(!ioc){
    alert("Please enter an indicator");
    return;
    }

    fetch('/api/threat-intel', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ioc: ioc})
    })
    .then(res => res.json())
    .then(data => {

        const resultDiv = document.getElementById("result");

        if (data.error) {
            resultDiv.innerHTML =
                `<p class="text-red-400">${data.error}</p>`;
            return;
        }

        /* DETERMINE VERDICT */

        let verdict = "SAFE";
        let verdictColor = "text-green-400";

        if (data.malicious > 0) {
            verdict = "MALICIOUS";
            verdictColor = "text-red-500";
        }
        else if (data.suspicious > 0) {
            verdict = "SUSPICIOUS";
            verdictColor = "text-yellow-400";
        }

        /* RENDER RESULT PANEL */

        resultDiv.innerHTML = `

        <div class="grid grid-cols-2 gap-6">

            <div class="bg-slate-800 p-6 rounded-xl">

                <h2 class="text-lg font-semibold mb-4">
                    Threat Verdict
                </h2>

                <p class="text-2xl font-bold ${verdictColor}">
                    ${verdict}
                </p>

                <table class="w-full text-sm mt-4">

                    <tr>
                        <td>Malicious</td>
                        <td class="text-red-400">${data.malicious}</td>
                    </tr>

                    <tr>
                        <td>Suspicious</td>
                        <td class="text-yellow-400">${data.suspicious}</td>
                    </tr>

                    <tr>
                        <td>Harmless</td>
                        <td class="text-green-400">${data.harmless}</td>
                    </tr>

                    <tr>
                        <td>Undetected</td>
                        <td>${data.undetected}</td>
                    </tr>

                    <tr>
                        <td>Reputation</td>
                        <td>${data.reputation}</td>
                    </tr>

                </table>

            </div>

            <div class="bg-slate-800 p-6 rounded-xl">

                <h2 class="text-lg font-semibold mb-4">
                    Detection Breakdown
                </h2>

                <canvas id="intelChart"></canvas>

            </div>

        </div>
        `;

        /* CREATE CHART */

        const ctx = document.getElementById("intelChart");

        if(chartInstance){
            chartInstance.destroy();
        }

        chartInstance = new Chart(ctx, {

            type: 'doughnut',

            data: {

                labels: [
                    'Malicious',
                    'Suspicious',
                    'Harmless',
                    'Undetected'
                ],

                datasets: [{

                    data: [
                        data.malicious,
                        data.suspicious,
                        data.harmless,
                        data.undetected
                    ],

                    backgroundColor: [
                        '#ef4444',
                        '#eab308',
                        '#22c55e',
                        '#64748b'
                    ]

                }]

            },

            options: {
                plugins:{
                    legend:{
                        position:'bottom',
                        labels:{
                            color:'#94a3b8'
                        }
                    }
                }
            }

        });

    })

    .catch(err => {

        document.getElementById("result").innerHTML =
            `<p class="text-red-400">Lookup failed</p>`;

    });

}