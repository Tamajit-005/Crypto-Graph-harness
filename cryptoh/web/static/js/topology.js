(function () {
  'use strict';

  const width = document.getElementById('topology')?.clientWidth || 800;
  const height = 260;

  const svg = d3.select('#topology').append('svg')
    .attr('width', '100%')
    .attr('height', height)
    .attr('viewBox', [0, 0, width, height]);

  const g = svg.append('g');
  svg.call(d3.zoom().on('zoom', (e) => g.attr('transform', e.transform)));

  const simulation = d3.forceSimulation()
    .force('link', d3.forceLink().id((d) => d.id).distance(60))
    .force('charge', d3.forceManyBody().strength(-180))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .on('tick', tick);

  let link = g.append('g').attr('stroke', '#555').attr('stroke-width', 1.5).selectAll('line');
  let node = g.append('g').selectAll('circle');

  function tick() {
    link.attr('x1', (d) => d.source.x).attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x).attr('y2', (d) => d.target.y);
    node.attr('cx', (d) => d.x).attr('cy', (d) => d.y);
  }

  window.renderTopology = function (dot) {
    const nodes = new Set();
    const edges = [];
    const re = /"([^"]+)"\s*->\s*"([^"]+)"/g;
    let m;
    while ((m = re.exec(dot)) !== null) {
      nodes.add(m[1]); nodes.add(m[2]);
      edges.push({ source: m[1], target: m[2] });
    }
    const data = { nodes: Array.from(nodes).map(id => ({ id })), links: edges };
    link = link.data(data.links, (d, i) => i).join('line')
      .attr('stroke', '#555')
      .attr('stroke-width', 1.5);
    node = node.data(data.nodes, (d) => d.id).join('circle')
      .attr('r', 6)
      .attr('fill', '#00ffff')
      .attr('stroke', '#e6e6e6')
      .call(drag(simulation));
    simulation.nodes(data.nodes);
    simulation.force('link').links(data.links);
    simulation.alpha(0.6).restart();
  };

  function drag(sim) {
    return d3.drag()
      .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; });
  }
})();
