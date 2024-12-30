document.addEventListener("DOMContentLoaded", function() {
  const currentDate = new Date();
  const currentMonth = currentDate.getMonth();
  let startDate;

  if (currentMonth < 6) {
      startDate = new Date(currentDate.getFullYear(), 1, 1);
  } else {
      startDate = new Date(currentDate.getFullYear(), 7, 1);
  }

  const cal = new CalHeatmap();
  cal.paint(
    {
      animationDuration: 500,
      theme: 'dark',
      data: {
        source: '/static/data/progress.json',
        type: 'json',
        x: 'date',
        y: d => d.value,
        groupY: 'max',
      },
      date: { start: startDate },
      range: 6,
      scale: {
        color: {
          type: 'threshold',
          range: ['#14432a', '#166b34', '#37a446', '#4dd05a'],
          domain: [2, 4, 6, 8, 10],
        },
      },
      domain: {
        type: 'month',
        gutter: 3,
        label: { text: 'MMM', textAlign: 'start', position: 'top' },
      },
      subDomain: { type: 'ghDay', radius: 3, width: 15, height: 15, gutter: 3 },
    },
  );
});
