var width  = 500;
var height = 500;
var margin = 20;
var pad = margin / 2;
var color = d3.scale.category20();
// Generates a tooltip for a SVG circle element based on its ID
function addTooltip(circle) {
    var x = parseFloat(circle.attr("cx"));
    var y = parseFloat(circle.attr("cy"));
    var r = parseFloat(circle.attr("r"));
    var text = circle.attr("id");
    var tooltip = d3.select("#plot")
        .append("text")
        .text(text)
        .attr("x", x)
        .attr("y", y)
        .attr("dy", -r * 2)
        .attr("id", "tooltip");
    var offset = tooltip.node().getBBox().width / 2;
    if ((x - offset) < 0) {
        tooltip.attr("text-anchor", "start");
        tooltip.attr("dx", -r);
    }
    else if ((x + offset) > (width - margin)) {
        tooltip.attr("text-anchor", "end");
        tooltip.attr("dx", r);
    }
    else {
        tooltip.attr("text-anchor", "middle");
        tooltip.attr("dx", 0);
    }
}
var vis = d3.select("#chart")
    .append("svg:svg")
    .attr("width", width)
    .attr("height", height)
    .attr("pointer-events", "all")
    .append('svg:g')
    .call(d3.behavior.zoom().on("zoom", redraw))
    .append('svg:g');
vis.append('svg:rect')
    .attr('width', width)
    .attr('height', height)
    .attr('fill', 'white');
function redraw() {
    console.log("here", d3.event.translate, d3.event.scale);
    vis.attr("transform",
        "translate(" + d3.event.translate + ")"
        + " scale(" + d3.event.scale + ")");
}
function drawGraph(graph) {
    var svg = d3.select("#force").append("svg")
        .attr("width", width)
        .attr("height", height);
    // draw plot background
    svg.append("rect")
        .attr("width", width)
        .attr("height", height)
        .style("fill", "#eeeeee");
    // create an area within svg for plotting graph
    var plot = svg.append("g")
        .attr("id", "plot")
        .attr("transform", "translate(" + pad + ", " + pad + ")");

    var edges = [];

    graph.links.forEach(function(e) { 
        // Get the source and target nodes
        var sourceNode = graph.nodes.filter(function(n) { return n.id === e.source; })[0],
            targetNode = graph.nodes.filter(function(n) { return n.id === e.target; })[0];
    
        // Add the edge to the array
        edges.push({source: sourceNode, target: targetNode});
    });    
    // https://github.com/mbostock/d3/wiki/Force-Layout#wiki-force
    var layout = d3.layout.force()
        .size([width - margin, height - margin])
        .charge(-120)
        .linkDistance(function(d, i) {
            return (d.source.group == d.target.group) ? 50 : 100;
        })
        .nodes(graph.nodes)
        .links(edges)
        .start();
    drawLinks(edges);
    drawNodes(graph.nodes);
    // add ability to drag and update layout
    // https://github.com/mbostock/d3/wiki/Force-Layout#wiki-drag
    d3.selectAll(".node").call(layout.drag);
    // https://github.com/mbostock/d3/wiki/Force-Layout#wiki-on
    layout.on("tick", function() {
        d3.selectAll(".link")
            .attr("x1", function(d) { return d.source.x; })
            .attr("y1", function(d) { return d.source.y; })
            .attr("x2", function(d) { return d.target.x; })
            .attr("y2", function(d) { return d.target.y; });
        d3.selectAll(".node")
            .attr("cx", function(d) { return d.x; })
            .attr("cy", function(d) { return d.y; });
    });
    var color = d3.scale.category20();
    var size = 20
    svg.selectAll("mydots")
    .data(graph.legend)
    .enter()
    .append("rect")
        .attr("x", 100)
        .attr("y", function(d,i){ return 100 + i*(size+5)}) // 100 is where the first dot appears. 25 is the distance between dots
        .attr("width", size)
        .attr("height", size)
        .style("fill", function(d){ return color(d)})

    // Add one dot in the legend for each name.
    svg.selectAll("mylabels")
    .data(graph.legend)
    .enter()
    .append("text")
        .attr("x", 100 + size*1.2)
        .attr("y", function(d,i){ return 100 + i*(size+5) + (size/2)}) // 100 is where the first dot appears. 25 is the distance between dots
        // .style("fill", function(d){ return color(d)})
        .text(function(d){ return d})
        .attr("text-anchor", "left")
        .style("alignment-baseline", "middle")
}
    function tick(e) {
    // Push different nodes in different directions for clustering.
    var k = 6 * e.alpha;
    graph.nodes.forEach(function(o, i) {
    o.y += i & 1 ? k : -k;
    o.x += i & 2 ? k : -k;
    });
    node.attr("cx", function(d) { return d.x; })
        .attr("cy", function(d) { return d.y; });
}
// Draws nodes on plot
function drawNodes(nodes) {
    // used to assign nodes color by group
    var color = d3.scale.category20();
    // https://github.com/mbostock/d3/wiki/Force-Layout#wiki-nodes
    d3.select("#plot").selectAll(".node")
        .data(nodes)
        .enter()
        .append("circle")
        .attr("class", "node")
        .attr("id", function(d, i) { return d.name; })
        .attr("cx", function(d, i) { return d.x; })
        .attr("cy", function(d, i) { return d.y; })
        .attr("r",  function(d, i) { return 15; })
        .style("fill",   function(d, i) { return color(d.group); })
        .on("mouseover", function(d, i) { addTooltip(d3.select(this)); })
        .on("mouseout",  function(d, i) { d3.select("#tooltip").remove(); });
}
// Draws edges between nodes
function drawLinks(links) {
    var scale = d3.scale.linear()
        .domain(d3.extent(links, function(d, i) {
            return d.value;
        }))
        .range([1, 6]);
    d3.select("#plot").selectAll(".link")
        .data(links)
        .enter()
        .append("line")
        .attr("class", "link")
        .attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; })
        .style("stroke-width", function(d, i) {
            return scale(d.value) + "px";
        })
        .style("stroke-dasharray", function(d, i) {
            return (d.value <= 1) ? "2, 2" : "none";
        });
}
