import express from "express";
import connectDb from "./db.js";
import Vuln from "./Data.js";
import path from "path";

let app = express();

app.use(express.static('./public'));


connectDb();

const fetchData = async () => {
    const url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const response = await fetch(url);
    const data = await response.json();
    for (let i = 0; i < data.vulnerabilities.length; i++) {
        const vuln = new Vuln({
            id: data.vulnerabilities[i].cve.id,
            sourceIdentifier: data.vulnerabilities[i].cve.sourceIdentifier,
            published: data.vulnerabilities[i].cve.published,
            lastModified: data.vulnerabilities[i].cve.lastModified,
            vulnStatus: data.vulnerabilities[i].cve.vulnStatus,
            descriptions: [{
                value: data.vulnerabilities[i].cve.descriptions[0].value,
            }],
            metrics: {
                cvssMetricV2: [{
                    baseSeverity: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].baseSeverity : "Unknown",
                    impactScore: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].impactScore : 0,
                    exploitabilityScore: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].exploitabilityScore : 0,
                    cvssData: {
                        vectorString: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.vectorString : "Unknown",
                        accessVector: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.accessVector : "Unknown",
                        accessComplexity: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.accessComplexity : "Unknown",
                        authentication: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.authentication : "Unknown",
                        confidentialityImpact: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.confidentialityImpact : "Unknown",
                        integrityImpact: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.integrityImpact : "Unknown",
                        availabilityImpact: data.vulnerabilities[i].cve.metrics.cvssMetricV2 && data.vulnerabilities[i].cve.metrics.cvssMetricV2.length > 0 ? data.vulnerabilities[i].cve.metrics.cvssMetricV2[0].cvssData.availabilityImpact : "Unknown",
                    }
                }]
            },
            configurations: [{
                nodes: [{
                    cpeMatch: [{
                        vulnerable: data.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch[0].vulnerable,
                        criteria: data.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch[0].criteria,
                        matchCriteriaId: data.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch[0].matchCriteriaId,
                    }]
                }]
            }]
        });
        // console.log(data.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch[0].matchCriteriaId);

        vuln.save();
    }

    console.log("Done");
};
fetchData();









app.get('/data', async (req, res) => {
    let page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';  // Get the search query from the request
    const cvss = req.query.cvss || ''; // Get the CVSS filter
    const published = req.query.published || ''; // Get the published date filter

    try {
        const query = {};

        if (search) {
            query.id = new RegExp(search, 'i'); // Regex for case-insensitive search
        }

        if (cvss) {
            query['metrics.cvssMetricV2.impactScore'] = parseFloat(cvss); // Filter for exact CVSS score
        }

        if (published) {
            // Convert the published date to the start of the day (00:00:00)
            const startDate = new Date(published);
            startDate.setHours(0, 0, 0, 0);
        
            // Convert the next day to the start of the day (00:00:00) for filtering
            const endDate = new Date(startDate);
            endDate.setDate(startDate.getDate() + 1);
        
            // Filter between the start and end of that day
            query.published = { $gte: startDate, $lt: endDate };
        }

        const totalRecords = await Vuln.countDocuments(query); // Get total record count with the filter

        // If searching by CVE ID and more than 1 record found, set totalRecords to 1 and page to 1
        if (search && totalRecords > 0) {
            page = 1; // Reset to the first page
        }

        const data = await Vuln.find(query)
            .skip((page - 1) * limit)  // Apply pagination
            .limit(limit);

        // Filter out duplicates by CVE ID
        const uniqueData = data.reduce((acc, vuln) => {
            if (!acc.some(item => item.id === vuln.id)) {
                acc.push(vuln);  // Add unique CVE ID
            }
            return acc;
        }, []); 

        // Add CVSS Score to each record
        const recordsWithScore = uniqueData.map(vuln => {
            const cvssScore = vuln.metrics.cvssMetricV2 && vuln.metrics.cvssMetricV2.length > 0 
                ? vuln.metrics.cvssMetricV2[0].impactScore
                : "Unknown";

            return {
                ...vuln.toObject(), // Spread existing vuln data
                cvssScore: cvssScore, // Add CVSS Score
            };
        });

        // If filtered by CVE ID, make total records 1
        if (search) {
            res.json({
                records: recordsWithScore.slice(0, 1), // Only return 1 record for the unique CVE ID search
                totalRecords: 1,
                page: 1
            });
        } else {
            res.json({
                records: recordsWithScore,
                totalRecords: totalRecords,  // Total records considering all filters
                page: page,  // Return current page number
            });
        }
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Failed to fetch data' });
    }
});



// Unique values without filter


// app.get('/data', async (req, res) => {
//     let page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;
//     const search = req.query.search || '';  // Get the search query from the request
//     const cvss = req.query.cvss || ''; // Get the CVSS filter
//     const published = req.query.published || ''; // Get the published date filter

//     try {
//         const query = {};

//         if (search) {
//             query.id = new RegExp(search, 'i'); // Regex for case-insensitive search
//         }

//         if (cvss) {
//             query['metrics.cvssMetricV2.impactScore'] = parseFloat(cvss); // Filter for exact CVSS score
//         }

//         if (published) {
//             // Convert the published date to the start of the day (00:00:00)
//             const startDate = new Date(published);
//             startDate.setHours(0, 0, 0, 0);
        
//             // Convert the next day to the start of the day (00:00:00) for filtering
//             const endDate = new Date(startDate);
//             endDate.setDate(startDate.getDate() + 1);
        
//             // Filter between the start and end of that day
//             query.published = { $gte: startDate, $lt: endDate };
//         }

//         const totalRecords = await Vuln.countDocuments(query); // Get total record count with the filter

//         // If searching by CVE ID and more than 1 record found, set totalRecords to 1 and page to 1
//         if (search && totalRecords > 0) {
//             page = 1; // Reset to the first page
//         }

//         const data = await Vuln.find(query)
//             .skip((page - 1) * limit)  // Apply pagination
//             .limit(limit);

//         // If the filter is by CVE ID (search), remove duplicates by CVE ID
//         const filteredData = search 
//             ? data.reduce((acc, vuln) => {
//                 if (!acc.some(item => item.id === vuln.id)) {
//                     acc.push(vuln);  // Add unique CVE ID
//                 }
//                 return acc;
//             }, [])
//             : data;  // If no search, return all data

//         // Add CVSS Score to each record
//         const recordsWithScore = filteredData.map(vuln => {
//             const cvssScore = vuln.metrics.cvssMetricV2 && vuln.metrics.cvssMetricV2.length > 0 
//                 ? vuln.metrics.cvssMetricV2[0].impactScore
//                 : "Unknown";

//             return {
//                 ...vuln.toObject(), // Spread existing vuln data
//                 cvssScore: cvssScore, // Add CVSS Score
//             };
//         });

//         // Send the response
//         res.json({
//             records: recordsWithScore,
//             totalRecords: totalRecords,  // Total records considering all filters
//             page: page,  // Return current page number
//         });
//     } catch (error) {
//         console.error('Error fetching data:', error);
//         res.status(500).json({ error: 'Failed to fetch data' });
//     }
// });










// Route for showing detailed CVE information
app.get('/details/:id', async (req, res) => {
    const { id } = req.params;  // Get the CVE ID from the URL params

    try {
        const vuln = await Vuln.findOne({ id }); // Find the vulnerability by its ID

        if (vuln) {
            const cvssMetrics = vuln.metrics.cvssMetricV2 && vuln.metrics.cvssMetricV2.length > 0
                ? vuln.metrics.cvssMetricV2[0]
                : null;

            const cpeDetails = vuln.configurations.reduce((acc, config) => {
                config.nodes.forEach(node => {
                    if (node.cpeMatch) {
                        node.cpeMatch.forEach(cpe => {
                            acc.push({
                                criteria: cpe.criteria || 'N/A',
                                matchCriteriaId: cpe.matchCriteriaId || 'N/A',
                                vulnerable: cpe.vulnerable ? 'Yes' : 'No'
                            });
                        });
                    }
                });
                return acc;
            }, []);

            res.json({
                id: vuln.id,
                description: vuln.descriptions.map(desc => desc.value).join(' '),
                cvssMetrics: {
                    severity: cvssMetrics ? cvssMetrics.baseSeverity : 'Unknown',
                    score: cvssMetrics ? cvssMetrics.baseScore : 'Unknown',
                    vectorString: cvssMetrics ? cvssMetrics.cvssData.vectorString : 'Unknown',
                    exploitabilityScore: cvssMetrics ? cvssMetrics.exploitabilityScore : 'Unknown',
                    impactScore: cvssMetrics ? cvssMetrics.impactScore : 'Unknown',
                    accessVector: cvssMetrics ? cvssMetrics.cvssData.accessVector : 'Unknown',
                    accessComplexity: cvssMetrics ? cvssMetrics.cvssData.accessComplexity : 'Unknown',
                    authentication: cvssMetrics ? cvssMetrics.cvssData.authentication : 'Unknown',
                    confidentialityImpact: cvssMetrics ? cvssMetrics.cvssData.confidentialityImpact : 'Unknown',
                    integrityImpact: cvssMetrics ? cvssMetrics.cvssData.integrityImpact : 'Unknown',
                    availabilityImpact: cvssMetrics ? cvssMetrics.cvssData.availabilityImpact : 'Unknown',
                },
                cpeDetails: cpeDetails
            });
        } else {
            res.status(404).json({ error: 'CVE not found' });
        }
    } catch (error) {
        console.error('Error fetching CVE details:', error);
        res.status(500).json({ error: 'Failed to fetch CVE details' });
    }
});







app.get('/cve/:id' ,(req, res) => {
    res.sendFile(path.join(process.cwd(), './public/details.html'))
})










app.get('/', (req, res) => {
    res.sendFile(path.join(process.cwd(), './public/index.html'));
});


app.listen(8000, () => {
    console.log("Server is running on port 8000");
});
