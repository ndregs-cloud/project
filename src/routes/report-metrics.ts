import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { auditStaffAccess } from './internal-audit.js';
import { parseInput, requireModerator } from '../validation.js';

const querySchema=z.object({days:z.coerce.number().int().min(1).max(180).default(30)});
export async function registerReportMetricsRoute(app:FastifyInstance):Promise<void>{
  app.get('/api/v1/moderation/reports/metrics',{config:{authRequired:true}},async(request)=>{
    const moderator=requireModerator(request);
    const {days}=parseInput(querySchema,request.query);
    await auditStaffAccess(app,moderator.id,'moderation_reports.metrics_read',null,{days});
    const categories=await app.pg.query(
      `SELECT reason AS category,count(*)::int AS volume,
         round(avg(extract(epoch FROM(first_response_at-created_at)))::numeric,1) AS "avgFirstResponseSeconds",
         sum(reopen_count)::int AS "reopenedCases"
       FROM reports WHERE created_at>=now()-($1::int*interval '1 day') GROUP BY reason ORDER BY volume DESC`,[days],
    );
    const recurring=await app.pg.query(
      `WITH repeated AS (
         SELECT target_type,target_id,count(*)::int AS volume FROM reports
         WHERE created_at>=now()-($1::int*interval '1 day')
         GROUP BY target_type,target_id HAVING count(*)>1
       ) SELECT target_type AS "targetType",count(*)::int AS "repeatedTargets",sum(volume)::int AS volume
         FROM repeated GROUP BY target_type ORDER BY volume DESC`,[days],
    );
    return {data:{windowDays:days,byCategory:categories.rows,recurringCases:recurring.rows}};
  });
}
