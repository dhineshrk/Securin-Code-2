import mongoose from "mongoose";

const vulnerabilitySchema = new mongoose.Schema({
  id: { type: String, required: true },
  sourceIdentifier: { type: String, required: true },
  published: { type: Date, required: false },
  lastModified: { type: Date, required: false },
  vulnStatus: { type: String, required: false },
  cveTags: { type: [String], default: [] },
  descriptions: [
    {
      lang: { type: String, required: false },
      value: { type: String, required: true },
    },
  ],
  metrics: {
    cvssMetricV2: [
      {
        source: { type: String, required: false },
        type: { type: String, required: false },
        cvssData: {
          version: { type: String, required: false },
          vectorString: { type: String, required: false },
          baseScore: { type: Number, required: false },
          accessVector: { type: String, required: false },
          accessComplexity: { type: String, required: false },
          authentication: { type: String, required: false },
          confidentialityImpact: { type: String, required: false },
          integrityImpact: { type: String, required: false },
          availabilityImpact: { type: String, required: false },
        },
        baseSeverity: { type: String, required: true },
        exploitabilityScore: { type: Number, required: false },
        impactScore: { type: Number, required: false },
        acInsufInfo: { type: Boolean, required: false },
        obtainAllPrivilege: { type: Boolean, required: false },
        obtainUserPrivilege: { type: Boolean, required: false },
        obtainOtherPrivilege: { type: Boolean, required: false },
        userInteractionRequired: { type: Boolean, required: false },
      },
    ],
  },
  weaknesses: [
    {
      source: { type: String, required: false },
      type: { type: String, required: false },
      description: [
        {
          lang: { type: String, required: false },
          value: { type: String, required: false },
        },
      ],
    },
  ],
  configurations: [
    {
      nodes: [
        {
          operator: { type: String, required: false },
          negate: { type: Boolean, required: false },
          cpeMatch: [
            {
              vulnerable: { type: Boolean, required: false },
              criteria: { type: String, required: false },
              matchCriteriaId: { type: String, required: false },
            },
          ],
        },
      ],
    },
  ],
  references: [
    {
      url: { type: String, required: false },
      source: { type: String, required: false },
    },
  ],
});

// vulnerabilitySchema.index({ id: 1 });
// vulnerabilitySchema.index({ publishedDate: 1 });

// Create the model
const Vuln = mongoose.model("Vulnerability", vulnerabilitySchema);

export default Vuln;
