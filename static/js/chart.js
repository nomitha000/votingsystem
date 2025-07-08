fetch("/api/results-data")
  .then(res => res.json())
  .then(data => {
    const ctx = document.getElementById("resultsChart").getContext("2d");

    const labels = data.map(c => c.name);
    const counts = data.map(c => c.count);
    const maxVotes = Math.max(...counts);
    const leader = data.find(c => c.count === maxVotes);

    document.getElementById("leader").innerText = `🎉 ${leader.name} is leading with ${leader.count} votes!`;

    new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Votes",
          data: counts,
          backgroundColor: "rgba(59, 130, 246, 0.7)"
        }]
      },
      options: {
        scales: {
          y: {
            beginAtZero: true,
            precision: 0
          }
        }
      }
    });
  });
